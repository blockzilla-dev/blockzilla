use crate::archive_cache::ArchiveByteCache;
use crate::archive_schema::{MessageSchema, MetadataSchema};
use crate::rpc_access::{
    BackendReadTracker, DirectCacheVariant, RpcApiKeyRecord, api_key_digest, direct_cache_identity,
    parse_bearer_key, rpc_method_for_metrics,
};
use crate::storage_metrics::{StorageBackend, StorageMetrics, StorageSnapshot};
mod base58;
mod block_base64;
mod bundle_object;
#[cfg(feature = "cli")]
pub mod client;
mod foundation_archive;
mod foundation_first;
mod native_hash;
mod native_reader;
mod recent_recovery;
mod resolution;
mod response_fill;
mod stored;
mod stream_parts;
mod transaction;
mod vote_proof;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use blockzilla_archive_v2::{
    ARCHIVE_V2_BLOCK_ACCESS_FILE, ARCHIVE_V2_BLOCKS_FILE, ARCHIVE_V2_GET_BLOCK_INDEX_FILE,
    ARCHIVE_V2_GET_BLOCK_INDEX_ROW_LEN, ARCHIVE_V2_TX_FLAG_HAS_METADATA,
    ARCHIVE_V2_TX_FLAG_METADATA_RAW_FALLBACK, ARCHIVE_V2_TX_FLAG_TX_RAW_FALLBACK,
    ArchiveV2BlockAccessBlob, ArchiveV2BlockAccessBlockhash, ArchiveV2BlockAccessPubkey,
    ArchiveV2GetBlockIndexRow, ArchiveV2HotBlockBlob, ArchiveV2HotBlockIndexRow,
    ArchiveV2HotInstructionData, ArchiveV2HotMessagePayload, ArchiveV2HotTxRow,
    ArchiveV2VoteHashRef, ArchiveV2VoteStateUpdate, ArchiveV2VoteTowerSync,
    BlockzillaGetBlockBlobEncoding, BlockzillaGetBlockBundleV1,
    WINCODE_ARCHIVE_V2_BLOCK_ACCESS_VERSION, WINCODE_BLOCKZILLA_GET_BLOCK_BUNDLE_VERSION,
    deserialize_archive_v2_hot_block_blob,
};
use blockzilla_compact::{
    CompactInnerInstructions, CompactInstructionError as InstructionError, CompactLogStream,
    CompactMetaV1, CompactReturnData, CompactReward, CompactTokenBalance, CompactTransactionConfig,
    CompactTransactionError as StoredTransactionError, LogEvent, OwnedCompactAddressTableLookup,
    OwnedCompactRecentBlockhash,
};
use blockzilla_primitives::{CompactPubkey, WincodeLeb128Config, wincode_leb128_config};
use blockzilla_program_logs::{program_logs, program_logs::ProgramLog};
use blockzilla_registry::KeyStore;
use futures_channel::mpsc;
use futures_util::{SinkExt, StreamExt, future};
use ruzstd::decoding::StreamingDecoder;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    io::{Read, Write},
    rc::Rc,
};
use wasm_bindgen::{JsCast, JsValue};
use wincode::{SchemaRead, io::Reader};
use worker::{
    AnalyticsEngineDataPointBuilder, AnalyticsEngineDataset, Bucket, Cache, Fetch, Headers, Method,
    Range as R2Range, Request, RequestInit, Response, Result, RouteContext, Router, console_error,
    event,
};

const SIGNATURE_BYTES: u64 = 64;
const SLOTS_PER_EPOCH: u64 = 432_000;

const BLOCK_CACHE_CONTROL: &str = "public, max-age=31536000, immutable";
const INFO_CACHE_CONTROL: &str = "public, max-age=30";
const ERROR_CACHE_CONTROL: &str = "no-store";
const LOG_MESSAGES_BYTES_LIMIT: usize = 10 * 1000;
const RPC_API_KEYS_BINDING: &str = "BZ_RPC_API_KEYS";
const RPC_METRICS_BINDING: &str = "BZ_RPC_METRICS";
const RPC_REQUEST_BODY_MAX_BYTES: usize = 1024 * 1024;
const MAX_ARCHIVE_RANGE_BYTES: usize = 16 * 1024 * 1024;
const MAX_DECODED_BLOCK_BYTES: usize = 32 * 1024 * 1024;
const MAX_CACHED_RANGE_BYTES: usize = 1024 * 1024;

// Only immutable archive bytes enter this cache. Keys include the complete
// source identity and an explicit publication generation. No request handles,
// credentials, API-key records, or customer data are retained here.
thread_local! {
    static ARCHIVE_BYTES: RefCell<ArchiveByteCache> = RefCell::new(ArchiveByteCache::new(4 * 1024 * 1024, 512));
}

#[derive(Clone)]
struct ArchiveCache {
    origin: String,
    generation: String,
    context: Rc<worker::Context>,
}

fn base58_32(bytes: &[u8; 32]) -> String {
    let mut buf = [0u8; five8::BASE58_ENCODED_32_MAX_LEN];
    let len = five8::encode_32(bytes, &mut buf) as usize;
    // five8 writes only Bitcoin base58 alphabet bytes, which are valid UTF-8.
    unsafe { String::from_utf8_unchecked(buf[..len].to_vec()) }
}

fn base58_64(bytes: &[u8; 64]) -> String {
    let mut buf = [0u8; five8::BASE58_ENCODED_64_MAX_LEN];
    let len = five8::encode_64(bytes, &mut buf) as usize;
    // five8 writes only Bitcoin base58 alphabet bytes, which are valid UTF-8.
    unsafe { String::from_utf8_unchecked(buf[..len].to_vec()) }
}

fn base58_bytes(bytes: &[u8]) -> String {
    match bytes.len() {
        32 => base58_32(bytes.try_into().expect("checked 32-byte base58 input")),
        64 => base58_64(bytes.try_into().expect("checked 64-byte base58 input")),
        _ => base58::encode(bytes),
    }
}

const JSON_STREAM_CHUNK_BYTES: usize = 64 * 1024;

struct JsonByteWriter {
    output: JsonByteOutput,
    // One bounded request-local table; it holds completed immutable encodings,
    // never request handles or live I/O. Allocate only when a key is written.
    encoded_keys: Vec<EncodedJsonKey>,
}

#[derive(Clone, Copy)]
struct EncodedJsonKey {
    key: [u8; 32],
    quoted: [u8; five8::BASE58_ENCODED_32_MAX_LEN + 2],
    len: u8,
}

const ENCODED_JSON_KEYS: usize = 256;
const EMPTY_ENCODED_JSON_KEY: EncodedJsonKey = EncodedJsonKey {
    key: [0; 32],
    quoted: [0; five8::BASE58_ENCODED_32_MAX_LEN + 2],
    len: 0,
};

enum JsonByteOutput {
    Buffered(Vec<u8>),
    Channel {
        sender: mpsc::Sender<std::result::Result<Vec<u8>, worker::Error>>,
        current: Vec<u8>,
        threshold: usize,
        len: usize,
        sent_bytes: usize,
        max_capacity: usize,
        failed: bool,
    },
}

impl JsonByteWriter {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            output: JsonByteOutput::Buffered(Vec::with_capacity(capacity)),
            encoded_keys: Vec::new(),
        }
    }

    fn channel(
        threshold: usize,
        sender: mpsc::Sender<std::result::Result<Vec<u8>, worker::Error>>,
    ) -> Self {
        let threshold = threshold.max(1024);
        Self {
            output: JsonByteOutput::Channel {
                sender,
                current: Vec::with_capacity(threshold),
                threshold,
                len: 0,
                sent_bytes: 0,
                max_capacity: threshold,
                failed: false,
            },
            encoded_keys: Vec::new(),
        }
    }

    fn into_inner(self) -> Vec<u8> {
        match self.output {
            JsonByteOutput::Buffered(out) => out,
            JsonByteOutput::Channel { .. } => Vec::new(),
        }
    }

    fn len(&self) -> usize {
        match &self.output {
            JsonByteOutput::Buffered(out) => out.len(),
            JsonByteOutput::Channel { len, .. } => *len,
        }
    }

    fn sent_bytes(&self) -> usize {
        match &self.output {
            JsonByteOutput::Buffered(_) => 0,
            JsonByteOutput::Channel { sent_bytes, .. } => *sent_bytes,
        }
    }

    fn pending_bytes(&self) -> usize {
        match &self.output {
            JsonByteOutput::Buffered(bytes) => bytes.len(),
            JsonByteOutput::Channel { current, .. } => current.len(),
        }
    }

    fn capacity(&self) -> usize {
        match &self.output {
            JsonByteOutput::Buffered(out) => out.capacity(),
            JsonByteOutput::Channel { max_capacity, .. } => *max_capacity,
        }
    }

    fn raw(&mut self, bytes: &[u8]) {
        self.write_raw(bytes);
    }

    fn string(&mut self, value: &str) -> std::result::Result<(), String> {
        serde_json::to_writer(&mut *self, value).map_err(|err| err.to_string())
    }

    fn json<T: Serialize + ?Sized>(&mut self, value: &T) -> std::result::Result<(), String> {
        serde_json::to_writer(&mut *self, value).map_err(|err| err.to_string())
    }

    fn u64(&mut self, value: u64) {
        let mut buffer = itoa::Buffer::new();
        self.raw(buffer.format(value).as_bytes());
    }

    fn i64(&mut self, value: i64) {
        let mut buffer = itoa::Buffer::new();
        self.raw(buffer.format(value).as_bytes());
    }

    fn json_bool(&mut self, value: bool) {
        self.raw(if value { b"true" } else { b"false" });
    }

    fn option_i64(&mut self, value: Option<i64>) {
        if let Some(value) = value {
            self.i64(value);
        } else {
            self.raw(b"null");
        }
    }

    fn option_u64(&mut self, value: Option<u64>) {
        if let Some(value) = value {
            self.u64(value);
        } else {
            self.raw(b"null");
        }
    }

    fn option_u8(&mut self, value: Option<u8>) {
        if let Some(value) = value {
            self.u64(u64::from(value));
        } else {
            self.raw(b"null");
        }
    }

    fn base58_32(&mut self, bytes: &[u8; 32]) {
        if self.encoded_keys.is_empty() {
            self.encoded_keys
                .resize(ENCODED_JSON_KEYS, EMPTY_ENCODED_JSON_KEY);
        }
        // Public keys are normally distributed. A collision changes only the
        // hit rate: every lookup compares all 32 bytes before reuse.
        let hash = u32::from_le_bytes(bytes[..4].try_into().expect("four bytes"))
            ^ u32::from_le_bytes(bytes[12..16].try_into().expect("four bytes"))
            ^ u32::from_le_bytes(bytes[28..].try_into().expect("four bytes"));
        let index = (hash.wrapping_mul(0x9e37_79b1) >> 24) as usize;
        let entry = &mut self.encoded_keys[index];
        if entry.len == 0 || entry.key != *bytes {
            let output: &mut [u8; five8::BASE58_ENCODED_32_MAX_LEN] = (&mut entry.quoted
                [1..five8::BASE58_ENCODED_32_MAX_LEN + 1])
                .try_into()
                .expect("fixed Base58 buffer");
            let len = five8::encode_32(bytes, output) as usize;
            entry.key = *bytes;
            entry.quoted[0] = b'"';
            entry.quoted[len + 1] = b'"';
            entry.len = (len + 2) as u8;
        }
        Self::append_output(&mut self.output, &entry.quoted[..entry.len as usize]);
    }

    fn base58_64(&mut self, bytes: &[u8; 64]) {
        let mut quoted = [b'"'; five8::BASE58_ENCODED_64_MAX_LEN + 2];
        let output: &mut [u8; five8::BASE58_ENCODED_64_MAX_LEN] = (&mut quoted
            [1..five8::BASE58_ENCODED_64_MAX_LEN + 1])
            .try_into()
            .expect("fixed Base58 buffer");
        let len = five8::encode_64(bytes, output) as usize;
        quoted[len + 1] = b'"';
        self.raw(&quoted[..len + 2]);
    }

    fn quoted_ui_amount(&mut self, digits: &[u8], decimals: u8) {
        self.raw(b"\"");
        if decimals == 0 || digits == b"0" {
            self.raw(digits);
        } else if digits.len() > usize::from(decimals) {
            let split = digits.len() - usize::from(decimals);
            self.raw(&digits[..split]);
            let mut end = digits.len();
            while end > split && digits[end - 1] == b'0' {
                end -= 1;
            }
            if end > split {
                self.raw(b".");
                self.raw(&digits[split..end]);
            }
        } else {
            // u8 decimals cap the fractional field at 255 digits.
            let mut output = [b'0'; 257];
            output[1] = b'.';
            let start = 2 + usize::from(decimals) - digits.len();
            output[start..start + digits.len()].copy_from_slice(digits);
            let mut end = start + digits.len();
            while output[end - 1] == b'0' {
                end -= 1;
            }
            self.raw(&output[..end]);
        }
        self.raw(b"\"");
    }

    fn u8_array(&mut self, values: &[u8]) {
        self.raw(b"[");
        for (index, value) in values.iter().enumerate() {
            if index > 0 {
                self.raw(b",");
            }
            self.u64(u64::from(*value));
        }
        self.raw(b"]");
    }

    fn u64_array(&mut self, values: &[u64]) {
        self.raw(b"[");
        for (index, value) in values.iter().enumerate() {
            if index > 0 {
                self.raw(b",");
            }
            self.u64(*value);
        }
        self.raw(b"]");
    }

    fn write_raw(&mut self, bytes: &[u8]) {
        Self::append_output(&mut self.output, bytes);
    }

    fn append_output(output: &mut JsonByteOutput, bytes: &[u8]) {
        match output {
            JsonByteOutput::Buffered(out) => out.extend_from_slice(bytes),
            JsonByteOutput::Channel {
                current,
                len,
                max_capacity,
                ..
            } => {
                *len = len.saturating_add(bytes.len());
                // Flush points are asynchronous and remain at record
                // boundaries. Splitting this synchronous append did not bound
                // the chunk: after threshold it copied one byte per iteration.
                current.extend_from_slice(bytes);
                *max_capacity = (*max_capacity).max(current.capacity());
            }
        }
    }

    async fn flush_chunk_async(&mut self) -> std::result::Result<(), String> {
        if let JsonByteOutput::Channel {
            sender,
            current,
            threshold,
            sent_bytes,
            max_capacity,
            failed,
            ..
        } = &mut self.output
        {
            if *failed || current.is_empty() {
                return Ok(());
            }
            let chunk = std::mem::take(current);
            *current = Vec::with_capacity(*threshold);
            *max_capacity = (*max_capacity).max(current.capacity());
            let chunk_len = chunk.len();
            if sender.send(Ok(chunk)).await.is_err() {
                *failed = true;
                return Err("response stream closed before chunk could be sent".to_string());
            }
            *sent_bytes = sent_bytes.saturating_add(chunk_len);
        }
        Ok(())
    }
}

impl Write for JsonByteWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.write_raw(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod json_writer_tests {
    use super::*;
    use futures_util::FutureExt;

    #[test]
    fn channel_preserves_record_bytes_and_flush_boundaries() {
        let (sender, mut receiver) = mpsc::channel(4);
        let mut writer = JsonByteWriter::channel(1024, sender);
        let prefix = vec![b'a'; 1017];
        let record = vec![b'b'; 2301];
        writer.raw(&prefix);
        writer.raw(&record);
        assert_eq!(writer.pending_bytes(), prefix.len() + record.len());
        assert_eq!(writer.sent_bytes(), 0);
        writer.flush_chunk_async().now_or_never().unwrap().unwrap();
        let chunk = receiver.next().now_or_never().unwrap().unwrap().unwrap();
        assert_eq!(chunk, [prefix, record].concat());
        assert_eq!(writer.pending_bytes(), 0);
        assert_eq!(writer.len(), chunk.len());
        assert_eq!(writer.sent_bytes(), chunk.len());
    }

    #[test]
    fn closed_channel_aborts_without_claiming_delivery() {
        let (sender, receiver) = mpsc::channel(1);
        let mut writer = JsonByteWriter::channel(1024, sender);
        writer.raw(b"{\"unfinished\":");
        drop(receiver);
        let error = writer
            .flush_chunk_async()
            .now_or_never()
            .unwrap()
            .unwrap_err();
        assert!(error.contains("response stream closed"));
        assert_eq!(writer.sent_bytes(), 0);
    }

    #[test]
    fn key_memo_is_lazy_bounded_and_collision_safe() {
        let mut writer = JsonByteWriter::with_capacity(0);
        assert!(writer.encoded_keys.is_empty());
        let mut collision = [0; 32];
        collision[4] = 255; // Same hash words as the all-zero key.
        let keys = [[0; 32], collision, [0; 32], [255; 32], [1; 32], collision];
        let mut expected = Vec::new();
        for key in &keys {
            writer.base58_32(key);
            expected
                .extend_from_slice(&serde_json::to_vec(&bs58::encode(key).into_string()).unwrap());
        }
        for value in 0u32..1024 {
            let mut key = [99; 32];
            key[..4].copy_from_slice(&value.to_le_bytes());
            writer.base58_32(&key);
            expected
                .extend_from_slice(&serde_json::to_vec(&bs58::encode(key).into_string()).unwrap());
        }
        assert_eq!(writer.encoded_keys.len(), ENCODED_JSON_KEYS);
        assert!(std::mem::size_of::<EncodedJsonKey>() * ENCODED_JSON_KEYS <= 20 * 1024);
        assert_eq!(writer.into_inner(), expected);
    }

    #[test]
    fn quoted_signatures_match_reference_without_allocating_key_memo() {
        for signature in [[0; 64], [1; 64], [255; 64]] {
            let mut writer = JsonByteWriter::with_capacity(0);
            writer.base58_64(&signature);
            assert!(writer.encoded_keys.is_empty());
            assert_eq!(
                writer.into_inner(),
                serde_json::to_vec(&bs58::encode(signature).into_string()).unwrap()
            );
        }
    }

    #[test]
    fn decimal_strings_match_existing_rpc_formatter_for_all_u8_scales() {
        for decimals in 0u8..=255 {
            for amount in [0u64, 1, 5, 10, 100, 123_456, 1_000_000_000, u64::MAX] {
                let mut digits = itoa::Buffer::new();
                let mut writer = JsonByteWriter::with_capacity(0);
                writer.quoted_ui_amount(digits.format(amount).as_bytes(), decimals);
                assert_eq!(
                    writer.into_inner(),
                    serde_json::to_vec(&ui_amount_string(amount, decimals)).unwrap(),
                    "amount={amount} decimals={decimals}"
                );
            }
        }
    }
}

fn stream_optional_transaction_error(
    w: &mut JsonByteWriter,
    err: Option<&StoredTransactionError>,
) -> std::result::Result<(), String> {
    if let Some(err) = err {
        stream_stored_transaction_error(w, err)
    } else {
        w.raw(b"null");
        Ok(())
    }
}

fn stream_transaction_status(
    w: &mut JsonByteWriter,
    err: Option<&StoredTransactionError>,
) -> std::result::Result<(), String> {
    if let Some(err) = err {
        w.raw(b"{\"Err\":");
        stream_stored_transaction_error(w, err)?;
        w.raw(b"}");
    } else {
        w.raw(br#"{"Ok":null}"#);
    }
    Ok(())
}

fn stream_stored_transaction_error(
    w: &mut JsonByteWriter,
    err: &StoredTransactionError,
) -> std::result::Result<(), String> {
    match err {
        StoredTransactionError::AccountInUse => w.string("AccountInUse"),
        StoredTransactionError::AccountLoadedTwice => w.string("AccountLoadedTwice"),
        StoredTransactionError::AccountNotFound => w.string("AccountNotFound"),
        StoredTransactionError::ProgramAccountNotFound => w.string("ProgramAccountNotFound"),
        StoredTransactionError::InsufficientFundsForFee => w.string("InsufficientFundsForFee"),
        StoredTransactionError::InvalidAccountForFee => w.string("InvalidAccountForFee"),
        StoredTransactionError::AlreadyProcessed => w.string("AlreadyProcessed"),
        StoredTransactionError::BlockhashNotFound => w.string("BlockhashNotFound"),
        StoredTransactionError::InstructionError(index, err) => {
            w.raw(b"{\"InstructionError\":[");
            w.u64(u64::from(*index));
            w.raw(b",");
            stream_instruction_error(w, err)?;
            w.raw(b"]}");
            Ok(())
        }
        StoredTransactionError::CallChainTooDeep => w.string("CallChainTooDeep"),
        StoredTransactionError::MissingSignatureForFee => w.string("MissingSignatureForFee"),
        StoredTransactionError::InvalidAccountIndex => w.string("InvalidAccountIndex"),
        StoredTransactionError::SignatureFailure => w.string("SignatureFailure"),
        StoredTransactionError::InvalidProgramForExecution => {
            w.string("InvalidProgramForExecution")
        }
        StoredTransactionError::SanitizeFailure => w.string("SanitizeFailure"),
        StoredTransactionError::ClusterMaintenance => w.string("ClusterMaintenance"),
        StoredTransactionError::AccountBorrowOutstanding => w.string("AccountBorrowOutstanding"),
        StoredTransactionError::WouldExceedMaxBlockCostLimit => {
            w.string("WouldExceedMaxBlockCostLimit")
        }
        StoredTransactionError::UnsupportedVersion => w.string("UnsupportedVersion"),
        StoredTransactionError::InvalidWritableAccount => w.string("InvalidWritableAccount"),
        StoredTransactionError::WouldExceedMaxAccountCostLimit => {
            w.string("WouldExceedMaxAccountCostLimit")
        }
        StoredTransactionError::WouldExceedAccountDataBlockLimit => {
            w.string("WouldExceedAccountDataBlockLimit")
        }
        StoredTransactionError::TooManyAccountLocks => w.string("TooManyAccountLocks"),
        StoredTransactionError::AddressLookupTableNotFound => {
            w.string("AddressLookupTableNotFound")
        }
        StoredTransactionError::InvalidAddressLookupTableOwner => {
            w.string("InvalidAddressLookupTableOwner")
        }
        StoredTransactionError::InvalidAddressLookupTableData => {
            w.string("InvalidAddressLookupTableData")
        }
        StoredTransactionError::InvalidAddressLookupTableIndex => {
            w.string("InvalidAddressLookupTableIndex")
        }
        StoredTransactionError::InvalidRentPayingAccount => w.string("InvalidRentPayingAccount"),
        StoredTransactionError::WouldExceedMaxVoteCostLimit => {
            w.string("WouldExceedMaxVoteCostLimit")
        }
        StoredTransactionError::WouldExceedAccountDataTotalLimit => {
            w.string("WouldExceedAccountDataTotalLimit")
        }
        StoredTransactionError::DuplicateInstruction(index) => {
            w.raw(b"{\"DuplicateInstruction\":");
            w.u64(u64::from(*index));
            w.raw(b"}");
            Ok(())
        }
        StoredTransactionError::InsufficientFundsForRent { account_index } => {
            w.raw(b"{\"InsufficientFundsForRent\":{\"account_index\":");
            w.u64(u64::from(*account_index));
            w.raw(b"}}");
            Ok(())
        }
        StoredTransactionError::MaxLoadedAccountsDataSizeExceeded => {
            w.string("MaxLoadedAccountsDataSizeExceeded")
        }
        StoredTransactionError::InvalidLoadedAccountsDataSizeLimit => {
            w.string("InvalidLoadedAccountsDataSizeLimit")
        }
        StoredTransactionError::ResanitizationNeeded => w.string("ResanitizationNeeded"),
        StoredTransactionError::ProgramExecutionTemporarilyRestricted { account_index } => {
            w.raw(b"{\"ProgramExecutionTemporarilyRestricted\":{\"account_index\":");
            w.u64(u64::from(*account_index));
            w.raw(b"}}");
            Ok(())
        }
        StoredTransactionError::UnbalancedTransaction => w.string("UnbalancedTransaction"),
        StoredTransactionError::ProgramCacheHitMaxLimit => w.string("ProgramCacheHitMaxLimit"),
        StoredTransactionError::CommitCancelled => w.string("CommitCancelled"),
    }
}

fn stream_instruction_error(
    w: &mut JsonByteWriter,
    err: &InstructionError,
) -> std::result::Result<(), String> {
    match err {
        InstructionError::GenericError => w.string("GenericError"),
        InstructionError::InvalidArgument => w.string("InvalidArgument"),
        InstructionError::InvalidInstructionData => w.string("InvalidInstructionData"),
        InstructionError::InvalidAccountData => w.string("InvalidAccountData"),
        InstructionError::AccountDataTooSmall => w.string("AccountDataTooSmall"),
        InstructionError::InsufficientFunds => w.string("InsufficientFunds"),
        InstructionError::IncorrectProgramId => w.string("IncorrectProgramId"),
        InstructionError::MissingRequiredSignature => w.string("MissingRequiredSignature"),
        InstructionError::AccountAlreadyInitialized => w.string("AccountAlreadyInitialized"),
        InstructionError::UninitializedAccount => w.string("UninitializedAccount"),
        InstructionError::UnbalancedInstruction => w.string("UnbalancedInstruction"),
        InstructionError::ModifiedProgramId => w.string("ModifiedProgramId"),
        InstructionError::ExternalAccountLamportSpend => w.string("ExternalAccountLamportSpend"),
        InstructionError::ExternalAccountDataModified => w.string("ExternalAccountDataModified"),
        InstructionError::ReadonlyLamportChange => w.string("ReadonlyLamportChange"),
        InstructionError::ReadonlyDataModified => w.string("ReadonlyDataModified"),
        InstructionError::DuplicateAccountIndex => w.string("DuplicateAccountIndex"),
        InstructionError::ExecutableModified => w.string("ExecutableModified"),
        InstructionError::RentEpochModified => w.string("RentEpochModified"),
        InstructionError::NotEnoughAccountKeys => w.string("NotEnoughAccountKeys"),
        InstructionError::AccountDataSizeChanged => w.string("AccountDataSizeChanged"),
        InstructionError::AccountNotExecutable => w.string("AccountNotExecutable"),
        InstructionError::AccountBorrowFailed => w.string("AccountBorrowFailed"),
        InstructionError::AccountBorrowOutstanding => w.string("AccountBorrowOutstanding"),
        InstructionError::DuplicateAccountOutOfSync => w.string("DuplicateAccountOutOfSync"),
        InstructionError::Custom(code) => {
            w.raw(b"{\"Custom\":");
            w.u64(u64::from(*code));
            w.raw(b"}");
            Ok(())
        }
        InstructionError::InvalidError => w.string("InvalidError"),
        InstructionError::ExecutableDataModified => w.string("ExecutableDataModified"),
        InstructionError::ExecutableLamportChange => w.string("ExecutableLamportChange"),
        InstructionError::ExecutableAccountNotRentExempt => {
            w.string("ExecutableAccountNotRentExempt")
        }
        InstructionError::UnsupportedProgramId => w.string("UnsupportedProgramId"),
        InstructionError::CallDepth => w.string("CallDepth"),
        InstructionError::MissingAccount => w.string("MissingAccount"),
        InstructionError::ReentrancyNotAllowed => w.string("ReentrancyNotAllowed"),
        InstructionError::MaxSeedLengthExceeded => w.string("MaxSeedLengthExceeded"),
        InstructionError::InvalidSeeds => w.string("InvalidSeeds"),
        InstructionError::InvalidRealloc => w.string("InvalidRealloc"),
        InstructionError::ComputationalBudgetExceeded => w.string("ComputationalBudgetExceeded"),
        InstructionError::PrivilegeEscalation => w.string("PrivilegeEscalation"),
        InstructionError::ProgramEnvironmentSetupFailure => {
            w.string("ProgramEnvironmentSetupFailure")
        }
        InstructionError::ProgramFailedToComplete => w.string("ProgramFailedToComplete"),
        InstructionError::ProgramFailedToCompile => w.string("ProgramFailedToCompile"),
        InstructionError::Immutable => w.string("Immutable"),
        InstructionError::IncorrectAuthority => w.string("IncorrectAuthority"),
        InstructionError::BorshIoError(_) => w.string("BorshIoError"),
        InstructionError::AccountNotRentExempt => w.string("AccountNotRentExempt"),
        InstructionError::InvalidAccountOwner => w.string("InvalidAccountOwner"),
        InstructionError::ArithmeticOverflow => w.string("ArithmeticOverflow"),
        InstructionError::UnsupportedSysvar => w.string("UnsupportedSysvar"),
        InstructionError::IllegalOwner => w.string("IllegalOwner"),
        InstructionError::MaxAccountsDataAllocationsExceeded => {
            w.string("MaxAccountsDataAllocationsExceeded")
        }
        InstructionError::MaxAccountsExceeded => w.string("MaxAccountsExceeded"),
        InstructionError::MaxInstructionTraceLengthExceeded => {
            w.string("MaxInstructionTraceLengthExceeded")
        }
        InstructionError::BuiltinProgramsMustConsumeComputeUnits => {
            w.string("BuiltinProgramsMustConsumeComputeUnits")
        }
    }
}

fn transaction_error_value(
    err: Option<&StoredTransactionError>,
) -> std::result::Result<Value, String> {
    let Some(err) = err else {
        return Ok(Value::Null);
    };
    let mut w = JsonByteWriter::with_capacity(64);
    stream_stored_transaction_error(&mut w, err)?;
    serde_json::from_slice(&w.into_inner())
        .map_err(|err| format!("parse transaction error JSON: {err}"))
}

#[derive(Clone)]
struct ProfileHandle(Rc<RefCell<RequestProfile>>);

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RequestProfile {
    started_ms: f64,
    source_ranges_only: bool,
    events: Vec<ProfileEvent>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProfileEvent {
    name: String,
    ms: f64,
    bytes: u64,
    detail: String,
    status: Option<u16>,
}

#[derive(Default)]
struct ProfileSummary {
    count: u32,
    total_ms: f64,
    bytes: u64,
}

impl ProfileHandle {
    fn new() -> Self {
        Self::with_source_ranges_only(false)
    }

    fn with_source_ranges_only(source_ranges_only: bool) -> Self {
        Self(Rc::new(RefCell::new(RequestProfile {
            started_ms: now_ms(),
            source_ranges_only,
            events: Vec::new(),
        })))
    }

    fn source_ranges_only(&self) -> bool {
        self.0.borrow().source_ranges_only
    }

    fn record_elapsed(
        &self,
        name: &str,
        started_ms: f64,
        bytes: u64,
        detail: impl Into<String>,
        status: Option<u16>,
    ) {
        self.0.borrow_mut().events.push(ProfileEvent {
            name: name.to_string(),
            ms: (now_ms() - started_ms).max(0.0),
            bytes,
            detail: detail.into(),
            status,
        });
    }

    fn profile_json(&self) -> Value {
        let profile = self.0.borrow();
        let mut summary = BTreeMap::<String, ProfileSummary>::new();
        for event in &profile.events {
            let entry = summary.entry(event.name.clone()).or_default();
            entry.count += 1;
            entry.total_ms += event.ms;
            entry.bytes += event.bytes;
        }
        let summary = summary
            .into_iter()
            .map(|(name, stats)| {
                json!({
                    "name": name,
                    "count": stats.count,
                    "totalMs": round_ms(stats.total_ms),
                    "bytes": stats.bytes,
                })
            })
            .collect::<Vec<_>>();
        json!({
            "totalMs": round_ms((now_ms() - profile.started_ms).max(0.0)),
            "cacheMode": if profile.source_ranges_only { "source" } else { "full" },
            "events": profile.events.iter().take(32).cloned().collect::<Vec<_>>(),
            "eventsTruncated": profile.events.len() > 32,
            "summary": summary,
        })
    }

    fn server_timing(&self) -> String {
        let profile = self.0.borrow();
        let mut summary = BTreeMap::<String, ProfileSummary>::new();
        for event in &profile.events {
            let entry = summary.entry(event.name.clone()).or_default();
            entry.count += 1;
            entry.total_ms += event.ms;
            entry.bytes += event.bytes;
        }
        summary
            .into_iter()
            .map(|(name, stats)| {
                format!(
                    "{};dur={:.2};desc=\"{}x {}B\"",
                    name, stats.total_ms, stats.count, stats.bytes
                )
            })
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn request_profile(req: &Request) -> Option<ProfileHandle> {
    let url = req.url().ok()?;
    let enabled = url.query_pairs().any(|(key, value)| {
        matches!(key.as_ref(), "debug" | "profile")
            && matches!(value.as_ref(), "1" | "true" | "yes" | "on")
    });
    if enabled {
        Some(ProfileHandle::new())
    } else {
        url.query_pairs()
            .any(|(key, value)| key == "profile" && value == "source")
            .then(|| ProfileHandle::with_source_ranges_only(true))
    }
}

fn allow_index_and_auth_cache(profile: Option<&ProfileHandle>) -> bool {
    profile.is_none_or(ProfileHandle::source_ranges_only)
}

#[cfg(not(target_arch = "wasm32"))]
fn now_ms() -> f64 {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    START
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_secs_f64()
        * 1000.0
}

#[cfg(target_arch = "wasm32")]
fn now_ms() -> f64 {
    let global = js_sys::global();
    if let Ok(performance) = js_sys::Reflect::get(&global, &JsValue::from_str("performance"))
        && !performance.is_null()
        && !performance.is_undefined()
        && let Ok(now) = js_sys::Reflect::get(&performance, &JsValue::from_str("now"))
        && let Some(now) = now.dyn_ref::<js_sys::Function>()
        && let Ok(value) = now.call0(&performance)
        && let Some(ms) = value.as_f64()
    {
        return ms;
    }
    js_sys::Date::now()
}

fn round_ms(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

#[event(fetch)]
async fn main(req: Request, env: worker::Env, ctx: worker::Context) -> Result<Response> {
    if req.method() == Method::Post
        && req.path() == "/"
        && optional_var(&env, "BZ_HTTP_GET_ONLY").as_deref() != Some("true")
    {
        return handle_rpc(req, env).await;
    }
    if req.method() != Method::Get {
        let mut response = json_error(405, "method_not_allowed", "Use HTTP GET")?;
        response.headers_mut().set("Allow", "GET")?;
        return Ok(response);
    }
    if req
        .path()
        .strip_prefix("/block/")
        .is_some_and(|path| path.ends_with(".resolution"))
    {
        return resolution::handle_index(req, env, ctx).await;
    }
    if req.method() == Method::Get && direct_block_route(&req.path()).is_some() {
        let path = req.path();
        let json = direct_block_route(&path)
            .is_some_and(|(_, slot)| direct_transport(slot) == "http_json");
        let response = handle_direct_block(req, env, ctx).await?;
        return if json && response.status_code() >= 400 {
            direct_json_rpc_error(response).await
        } else {
            Ok(response)
        };
    }

    Router::new()
        .get_async("/", handle_info)
        .get_async("/info", handle_info)
        .run(req, env)
        .await
}

async fn direct_json_rpc_error(mut response: Response) -> Result<Response> {
    let status = response.status_code();
    let headers = response.headers().clone();
    let value: Value = response.json().await?;
    let body = if value.get("jsonrpc").and_then(Value::as_str) == Some("2.0") {
        value
    } else {
        let code = if status == 400 { -32602 } else { -32000 };
        error_response(
            Value::from(1),
            code,
            value
                .pointer("/error/message")
                .and_then(Value::as_str)
                .unwrap_or("Block request failed"),
        )
    };
    headers.delete("Content-Length")?;
    Ok(Response::from_json(&body)?
        .with_status(status)
        .with_headers(headers))
}

async fn handle_direct_block(
    req: Request,
    env: worker::Env,
    ctx: worker::Context,
) -> Result<Response> {
    let ctx = Rc::new(ctx);
    let request_started = now_ms();
    let profile = request_profile(&req);
    let auth_started = now_ms();
    let auth = match authenticate_api_key_with_cache_policy(
        &req,
        &env,
        allow_index_and_auth_cache(profile.as_ref()),
    )
    .await
    {
        Ok(record) => record,
        Err(RpcAuthError::Unauthorized) => return api_unauthorized_response(),
        Err(RpcAuthError::Unavailable) => {
            return json_error_profiled(
                503,
                "api_unavailable",
                "API authentication is temporarily unavailable",
                profile.as_ref(),
            );
        }
    };
    if let Some(profile) = &profile {
        profile.record_elapsed("authentication", auth_started, 0, auth.cache_status, None);
        let placement = req.headers().get("cf-placement")?.unwrap_or_default();
        let colo = req.cf().map(|cf| cf.colo()).unwrap_or_default();
        profile.record_elapsed(
            "worker_placement",
            now_ms(),
            0,
            format!("colo={colo};placement={placement}"),
            None,
        );
    }
    let auth_cache_status = auth.cache_status;
    let auth_cache_tier = auth.cache_tier;
    let archive_backend = archive_backend_label(&env);
    let archive_layout = if optional_var(&env, "BZ_SLOT_BUNDLE_PREFIX").is_some() {
        "bundle-v1"
    } else {
        "compact-v2"
    };
    let mut response =
        handle_authenticated_direct_block(req, env, ctx, profile, auth.record, request_started)
            .await?;
    add_auth_cache_headers(&mut response, auth_cache_status, auth_cache_tier)?;
    response
        .headers_mut()
        .set("X-Blockzilla-Archive-Backend", archive_backend)?;
    response
        .headers_mut()
        .set("X-Blockzilla-Archive-Layout", archive_layout)?;
    Ok(response)
}

fn archive_backend_label(env: &worker::Env) -> &'static str {
    if optional_var(env, "BZ_NATIVE_READER_URL").is_some() {
        return "reader";
    }
    match optional_var(env, "BZ_ARCHIVE_SOURCE")
        .as_deref()
        .unwrap_or("auto")
    {
        "r2" | "cloudflare" | "cloudflare-r2" => "r2",
        "s3" | "backblaze" | "b2" => "s3",
        "auto" if env.bucket(&r2_binding_name(env)).is_ok() => "r2",
        "auto" => "s3",
        _ => "unknown",
    }
}

fn add_auth_cache_headers(
    response: &mut Response,
    cache_status: &str,
    cache_tier: &str,
) -> Result<()> {
    response.headers_mut().set(
        "X-Blockzilla-Auth-Cache",
        &cache_status.to_ascii_uppercase(),
    )?;
    response.headers_mut().set(
        "X-Blockzilla-Auth-KV-Reads",
        if cache_status == "hit" { "0" } else { "1" },
    )?;
    response.headers_mut().set(
        "X-Blockzilla-Auth-Cache-Tier",
        &cache_tier.to_ascii_uppercase(),
    )?;
    Ok(())
}

async fn handle_authenticated_direct_block(
    req: Request,
    env: worker::Env,
    ctx: Rc<worker::Context>,
    profile: Option<ProfileHandle>,
    api_key: RpcApiKeyRecord,
    request_started: f64,
) -> Result<Response> {
    let metrics = match rpc_metrics(&env, profile.as_ref()) {
        Ok(metrics) => metrics,
        Err(response) => return Ok(response),
    };

    let path = req.path();
    let Some((mode, raw_slot)) = direct_block_route(&path) else {
        return finish_metered_response(
            json_error_profiled(400, "invalid_slot", "missing slot", profile.as_ref())?,
            &api_key,
            &metrics,
            MeteredRequest::new("invalid", "invalid_request", "bypass", "unknown", 0, 0),
            request_started,
            profile.as_ref(),
        );
    };
    let method = mode.metric_method();
    let transport = direct_transport(raw_slot);
    if mode == RouteBlockMode::Full && raw_slot.ends_with(".compact") {
        return recent_recovery::handle(
            req,
            env,
            ctx,
            profile,
            api_key,
            request_started,
            metrics,
            raw_slot,
        )
        .await;
    }
    let request = match parse_block_request(&req, raw_slot) {
        Ok(request) => request,
        Err(response) => {
            return finish_metered_response(
                response,
                &api_key,
                &metrics,
                MeteredRequest::new(method, "invalid_request", "bypass", transport, 0, 0),
                request_started,
                profile.as_ref(),
            );
        }
    };
    let r2_probe = req
        .url()?
        .query_pairs()
        .any(|(key, value)| key == "r2_probe" && value == "1");
    if r2_probe
        && (optional_var(&env, "BZ_R2_PROBE_ENABLED").as_deref() != Some("true")
            || profile.is_none()
            || mode != RouteBlockMode::Full
            || request.format != BlockResponseFormat::Wincode)
    {
        return finish_metered_response(
            json_error(
                404,
                "probe_unavailable",
                "R2 diagnostics are not enabled for this request",
            )?,
            &api_key,
            &metrics,
            MeteredRequest::new(method, "invalid_request", "bypass", transport, 0, 0),
            request_started,
            profile.as_ref(),
        );
    }
    if request.format == BlockResponseFormat::Wincode && req.headers().get("Range")?.is_some() {
        return finish_metered_response(
            json_error_profiled(
                400,
                "unsupported_range",
                "Range requests are not supported for direct binary responses",
                profile.as_ref(),
            )?,
            &api_key,
            &metrics,
            MeteredRequest::new(method, "invalid_request", "bypass", transport, 0, 0),
            request_started,
            profile.as_ref(),
        );
    }
    let access_mode = block_bin_access_mode(&req);
    let client_locator = resolution::query_locator(&req);
    let client_binary = req
        .url()?
        .query_pairs()
        .any(|(key, value)| key == "access" && value == "client");
    let json_hint = request.format == BlockResponseFormat::Json
        && mode == RouteBlockMode::Full
        && client_locator.is_some();
    let json_locator = if json_hint {
        client_locator.as_deref()
    } else {
        None
    };
    if client_binary && (request.format != BlockResponseFormat::Wincode || client_locator.is_none())
    {
        return finish_metered_response(
            json_error(
                400,
                "invalid_locator",
                "Client binary needs a locator from the resolution response",
            )?,
            &api_key,
            &metrics,
            MeteredRequest::new(method, "invalid_request", "bypass", transport, 0, 0),
            request_started,
            profile.as_ref(),
        );
    }
    let cache_key = if profile.is_none() {
        let mut key = canonical_block_cache_key(
            &req,
            request,
            mode,
            access_mode,
            &archive_cache_generation(&env),
        )?;
        if client_binary || json_hint {
            key.push_str("&client=");
            key.push_str(&api_key_digest(
                client_locator.as_deref().unwrap_or_default(),
            ));
        }
        Some(key)
    } else {
        None
    };
    let mut cache_status = "bypass";
    if let Some(cache_key) = cache_key.as_ref() {
        match Cache::default().get(cache_key.clone(), false).await {
            Ok(Some(response)) => {
                let mut response = response_with_mutable_headers(response);
                response
                    .headers_mut()
                    .set("Cache-Control", "private, no-store")?;
                response
                    .headers_mut()
                    .set("X-Blockzilla-Cache-Fill", "HIT")?;
                response
                    .headers_mut()
                    .set("X-Blockzilla-Foundation-Result", "RESPONSE_CACHE")?;
                return finish_metered_response(
                    response,
                    &api_key,
                    &metrics,
                    MeteredRequest::new(method, "ok", "hit", transport, 0, 0),
                    request_started,
                    profile.as_ref(),
                );
            }
            Ok(None) => cache_status = "miss",
            Err(err) => {
                console_error!(
                    "{}",
                    json!({
                        "event": "block_cache_error",
                        "operation": "get",
                        "error": err.to_string(),
                    })
                );
            }
        }
    }
    let mut fill_leader = None;
    let mut fill_status = "BYPASS";
    if cache_status == "miss"
        && let Some(key) = cache_key.as_ref()
    {
        match response_fill::admit(key) {
            response_fill::Admission::Leader(leader) => {
                fill_leader = Some(leader);
                fill_status = "LEADER";
            }
            response_fill::Admission::Follower(completion) => {
                if response_fill::wait(completion).await
                    && let Ok(Some(response)) = Cache::default().get(key.clone(), false).await
                {
                    let mut response = response_with_mutable_headers(response);
                    response
                        .headers_mut()
                        .set("Cache-Control", "private, no-store")?;
                    response
                        .headers_mut()
                        .set("X-Blockzilla-Cache-Fill", "COALESCED")?;
                    response
                        .headers_mut()
                        .set("X-Blockzilla-Foundation-Result", "RESPONSE_CACHE")?;
                    return finish_metered_response(
                        response,
                        &api_key,
                        &metrics,
                        MeteredRequest::new(method, "ok", "hit", transport, 0, 0),
                        request_started,
                        profile.as_ref(),
                    );
                }
                // A failed/evicted fill or a bounded wait must not make the
                // request depend on a missing cache entry. Read independently.
                fill_status = "FALLBACK";
            }
            response_fill::Admission::Untracked => {}
        }
    }
    let source = match WorkerSource::from_env(&env, profile.clone()) {
        Ok(mut source) => {
            if allow_index_and_auth_cache(profile.as_ref()) {
                source.cache = Some(ArchiveCache {
                    origin: req.url()?.origin().ascii_serialization(),
                    generation: archive_cache_generation(&env),
                    context: ctx.clone(),
                });
            }
            source
        }
        Err(err) => {
            return finish_metered_response(
                json_error_profiled(500, "config_error", &err, profile.as_ref())?,
                &api_key,
                &metrics,
                MeteredRequest::new(method, "config_error", cache_status, transport, 0, 0),
                request_started,
                profile.as_ref(),
            );
        }
    };

    // One lookup runs only after auth, response-cache lookup and fill admission.
    // The result is request-local; it is consumed by exactly one renderer.
    let mut foundation_status = "DISABLED";
    if let Some(config) = source.foundation_lookup.as_ref() {
        foundation_status = if config.archive_lookup_enabled() {
            "BYPASS"
        } else {
            "RECENT_ONLY"
        };
        if config.archive_lookup_enabled()
            && mode == RouteBlockMode::Full
            && client_locator.is_none()
            && !client_binary
            && access_mode == BlockBinAccessMode::Include
        {
            let route = foundation_archive::cached_route(&source, request.slot).await;
            let route_hit = route.is_some();
            let lookup = if let Some(route) = route {
                Ok(foundation_first::Outcome::NotCached {
                    source: Some(route),
                })
            } else {
                source.backend_read.mark();
                source.storage_metrics.attempt_foundation_lookup_http();
                config.lookup(&source, request.slot).await
            };
            match lookup {
                Ok(result @ foundation_first::Outcome::Complete { .. }) => {
                    foundation_status = "COMPLETE";
                    source.foundation_prepared.borrow_mut().replace(result);
                }
                Ok(result @ foundation_first::Outcome::Resolution { .. }) => {
                    foundation_status = "RESOLUTION";
                    source.foundation_prepared.borrow_mut().replace(result);
                }
                Ok(foundation_first::Outcome::NotCached {
                    source: Some(route),
                }) => {
                    foundation_status = if route_hit { "ROUTE_CACHE" } else { "ARCHIVE" };
                    if !route_hit {
                        foundation_archive::cache_route(&source, request.slot, &route);
                    }
                    source.foundation_prepared.borrow_mut().replace(
                        foundation_first::Outcome::NotCached {
                            source: Some(route),
                        },
                    );
                }
                Ok(foundation_first::Outcome::NotCached { source: None }) => {
                    foundation_status = "FALLBACK";
                }
                Ok(foundation_first::Outcome::TransportFailure(reason)) => {
                    foundation_status = "FALLBACK";
                    source.record_elapsed(
                        "foundation_fallback",
                        now_ms(),
                        0,
                        format!("{reason:?}"),
                        None,
                    );
                }
                Ok(foundation_first::Outcome::Unavailable(reason)) => {
                    let (status, code) = match reason {
                        foundation_first::Unavailable::Unavailable => (404, "block_unavailable"),
                        foundation_first::Unavailable::Pruned => (410, "block_pruned"),
                        foundation_first::Unavailable::Incomplete => (409, "block_incomplete"),
                        foundation_first::Unavailable::NotFinalized => (409, "block_not_finalized"),
                        foundation_first::Unavailable::CoverageUnavailable => {
                            (404, "coverage_unavailable")
                        }
                        foundation_first::Unavailable::SourceChanged => (409, "source_changed"),
                        foundation_first::Unavailable::HashMismatch => (409, "hash_mismatch"),
                    };
                    let mut response = json_error_profiled(status, code, code, profile.as_ref())?;
                    response
                        .headers_mut()
                        .set("X-Blockzilla-Foundation-Result", code)?;
                    return finish_metered_response(
                        response,
                        &api_key,
                        &metrics,
                        MeteredRequest::new(method, "not_found", cache_status, transport, 0, 0)
                            .with_storage(source.storage_metrics.snapshot()),
                        request_started,
                        profile.as_ref(),
                    );
                }
                Err(error) => {
                    let mut response = json_error_profiled(
                        502,
                        "foundation_lookup_error",
                        &error,
                        profile.as_ref(),
                    )?;
                    response
                        .headers_mut()
                        .set("X-Blockzilla-Foundation-Result", "REJECTED")?;
                    return finish_metered_response(
                        response,
                        &api_key,
                        &metrics,
                        MeteredRequest::new(method, "backend_error", cache_status, transport, 0, 0)
                            .with_storage(source.storage_metrics.snapshot()),
                        request_started,
                        profile.as_ref(),
                    );
                }
            }
        }
    }

    if source.foundation_prepared.borrow().is_none()
        && source.slot_bundle.is_some()
        && !bundle_object::covered(&source, request.slot)
    {
        return finish_metered_response(
            json_error_profiled(
                404,
                "block_unavailable",
                "This test serves only its admitted slot bundles",
                profile.as_ref(),
            )?,
            &api_key,
            &metrics,
            MeteredRequest::new(method, "not_found", cache_status, transport, 0, 0),
            request_started,
            profile.as_ref(),
        );
    }

    if profile
        .as_ref()
        .is_some_and(ProfileHandle::source_ranges_only)
        && !resolution::covered(&source, request.slot)
        && !bundle_object::covered(&source, request.slot)
        && source.foundation_prepared.borrow().is_none()
    {
        return finish_metered_response(
            json_error_profiled(
                400,
                "unsupported_profile",
                "Source-only profiling requires an admitted per-slot index",
                profile.as_ref(),
            )?,
            &api_key,
            &metrics,
            MeteredRequest::new(method, "invalid_request", "bypass", transport, 0, 0),
            request_started,
            profile.as_ref(),
        );
    }

    if r2_probe {
        let prepared = source.foundation_prepared.borrow_mut().take();
        let result = match prepared {
            Some(foundation_first::Outcome::NotCached {
                source: Some(route),
            }) => resolution::r2_probe_response(&source, request.slot, route).await,
            _ => Err("R2 diagnostics require an admitted Foundation archive route".into()),
        };
        let (mut response, outcome) = match result {
            Ok(response) => (response, "ok"),
            Err(error) => (
                json_error_profiled(502, "r2_probe_error", &error, profile.as_ref())?,
                "backend_error",
            ),
        };
        response
            .headers_mut()
            .set("X-Blockzilla-Foundation-Result", foundation_status)?;
        return finish_metered_response(
            response,
            &api_key,
            &metrics,
            MeteredRequest::new(
                method,
                outcome,
                "bypass",
                "http_r2_probe",
                0,
                source.billable_backend_reads(),
            )
            .with_storage(source.storage_metrics.snapshot()),
            request_started,
            profile.as_ref(),
        );
    }

    let route_started = now_ms();
    let (mut response, outcome) = match request.format {
        BlockResponseFormat::Json => {
            let buffered_profile = profile.is_some()
                && req
                    .url()?
                    .query_pairs()
                    .any(|(key, value)| key == "profile_body" && value == "buffered");
            let rendered = if buffered_profile {
                render_route_block_bytes(&source, request, mode, json_locator)
                    .await
                    .and_then(|body| {
                        body.map(|bytes| {
                            let mut response = json_bytes_response_profiled(
                                bytes,
                                ERROR_CACHE_CONTROL,
                                profile.as_ref(),
                            )
                            .map_err(|e| e.to_string())?;
                            response
                                .headers_mut()
                                .set("X-Blockzilla-Body", "profile-buffered")
                                .map_err(|e| e.to_string())?;
                            Ok(response)
                        })
                        .transpose()
                    })
            } else {
                render_route_block_response(&source, request, mode, json_locator).await
            };
            match rendered {
                Ok(Some(response)) => {
                    source.record_elapsed("route_total", route_started, 0, "json_streamed", None);
                    (response, "ok")
                }
                Ok(None) => {
                    source.record_elapsed("route_total", route_started, 0, "json_empty", None);
                    (
                        cached_json_response_profiled(
                            &success_response(Value::from(1), Value::Null),
                            ERROR_CACHE_CONTROL,
                            profile.as_ref(),
                        )?,
                        "not_found",
                    )
                }
                Err(err) => {
                    console_error!("block route failed for slot {}: {}", request.slot, err);
                    source.record_elapsed("route_total", route_started, 0, "json_error", None);
                    (
                        json_rpc_response_profiled(
                            error_response(
                                Value::from(1),
                                -32000,
                                format!("failed to fetch slot {}: {err}", request.slot),
                            ),
                            profile.as_ref(),
                        )?
                        .with_status(502),
                        "backend_error",
                    )
                }
            }
        }
        BlockResponseFormat::Wincode => {
            let prepared = source.foundation_prepared.borrow_mut().take();
            if let Some(prepared) = prepared {
                match foundation_binary_response(
                    &source,
                    request.slot,
                    prepared,
                    &ctx,
                    &metrics,
                    &api_key,
                )
                .await
                {
                    Ok(response) => (response, "ok"),
                    Err(error) => (
                        json_error_profiled(
                            502,
                            "foundation_block_error",
                            &error,
                            profile.as_ref(),
                        )?,
                        "backend_error",
                    ),
                }
            } else if bundle_object::covered(&source, request.slot) {
                if client_binary || access_mode != BlockBinAccessMode::Include {
                    (
                        json_error_profiled(
                            400,
                            "unsupported_bundle_variant",
                            "Stored slot bundles require full access data without a client locator",
                            profile.as_ref(),
                        )?,
                        "invalid_request",
                    )
                } else {
                    match bundle_object::binary_response(
                        &source,
                        request.slot,
                        &ctx,
                        &metrics,
                        &api_key,
                    )
                    .await
                    {
                        Ok(response) => (response, "ok"),
                        Err(err) => (
                            json_error_profiled(502, "bundle_error", &err, profile.as_ref())?,
                            "backend_error",
                        ),
                    }
                }
            } else if client_binary && !resolution::covered(&source, request.slot) {
                (
                    json_error_profiled(
                        400,
                        "invalid_locator",
                        "Client slot is outside admitted resolution coverage",
                        profile.as_ref(),
                    )?,
                    "invalid_request",
                )
            } else if resolution::covered(&source, request.slot) {
                match resolution::binary_response(
                    &source,
                    request.slot,
                    access_mode == BlockBinAccessMode::Include,
                    if client_binary {
                        client_locator.as_deref()
                    } else {
                        None
                    },
                    &ctx,
                    &metrics,
                    &api_key,
                )
                .await
                {
                    Ok(response) => (response, "ok"),
                    Err(err) => (
                        json_error_profiled(502, "resolution_error", &err, profile.as_ref())?,
                        "backend_error",
                    ),
                }
            } else {
                match fetch_block_bundle_bytes(&source, request.slot, access_mode).await {
                    Ok(Some(bytes)) => {
                        source.record_elapsed(
                            "route_total",
                            route_started,
                            bytes.len() as u64,
                            "wincode_bundle",
                            None,
                        );
                        (
                            block_bundle_response_profiled(bytes, profile.as_ref())?,
                            "ok",
                        )
                    }
                    Ok(None) => {
                        source.record_elapsed(
                            "route_total",
                            route_started,
                            0,
                            "wincode_empty",
                            None,
                        );
                        (
                            json_error_profiled(
                                404,
                                "block_unavailable",
                                "This archive has no block for the requested slot",
                                profile.as_ref(),
                            )?,
                            "not_found",
                        )
                    }
                    Err(err) => {
                        console_error!("wincode route failed for slot {}: {}", request.slot, err);
                        source.record_elapsed(
                            "route_total",
                            route_started,
                            0,
                            "wincode_error",
                            None,
                        );
                        (
                            json_error_profiled(
                                502,
                                "blockzilla_decode_error",
                                &format!("failed to fetch slot {}: {err}", request.slot),
                                profile.as_ref(),
                            )?,
                            "backend_error",
                        )
                    }
                }
            }
        }
    };
    let billable_backend_reads = source.billable_backend_reads();
    response
        .headers_mut()
        .set("X-Blockzilla-Foundation-Result", foundation_status)?;

    let cache_write = if outcome == "ok"
        && response.status_code() == 200
        && let Some(cache_key) = cache_key
    {
        match response.cloned() {
            Ok(cache_response) => Some((cache_key, cache_response)),
            Err(err) => {
                console_error!(
                    "{}",
                    json!({
                        "event": "block_cache_error",
                        "operation": "clone",
                        "error": err.to_string(),
                    })
                );
                None
            }
        }
    } else {
        None
    };

    // Only the programmatic Worker Cache owns reusable representations. The
    // client response stays private so an outer shared cache cannot skip auth.
    response
        .headers_mut()
        .set("Cache-Control", "private, no-store")?;
    response
        .headers_mut()
        .set("X-Blockzilla-Cache-Fill", fill_status)?;
    let response = finish_metered_response(
        response,
        &api_key,
        &metrics,
        MeteredRequest::new(
            method,
            outcome,
            cache_status,
            transport,
            0,
            billable_backend_reads,
        )
        .with_storage(source.storage_metrics.snapshot()),
        request_started,
        profile.as_ref(),
    )?;
    if response.status_code() != 503
        && let Some((cache_key, cache_response)) = cache_write
    {
        let fill_leader = fill_leader.take();
        ctx.wait_until(async move {
            let result = Cache::default().put(cache_key, cache_response).await;
            if let Some(leader) = fill_leader {
                leader.finish(result.is_ok());
            }
            if let Err(err) = result {
                console_error!(
                    "{}",
                    json!({
                        "event": "block_cache_error",
                        "operation": "put",
                        "error": err.to_string(),
                    })
                );
            }
        });
    }
    Ok(response)
}

fn response_with_mutable_headers(response: Response) -> Response {
    let status = response.status_code();
    let headers = response.headers().clone();
    let encode_body = *response.encode_body();
    let (_, body) = response.into_parts();
    Response::builder()
        .with_status(status)
        .with_headers(headers)
        .with_encode_body(encode_body)
        .body(body)
}

fn rpc_metrics(
    env: &worker::Env,
    profile: Option<&ProfileHandle>,
) -> std::result::Result<AnalyticsEngineDataset, Response> {
    env.analytics_engine(RPC_METRICS_BINDING).map_err(|_| {
        console_error!(
            "{}",
            json!({
                "event": "rpc_metrics_backend_error",
                "reason": "missing_binding",
            })
        );
        json_error_profiled(
            503,
            "api_unavailable",
            "API metering is temporarily unavailable",
            profile,
        )
        .unwrap_or_else(|_| Response::error("API unavailable", 503).unwrap())
    })
}

fn direct_block_route(path: &str) -> Option<(RouteBlockMode, &str)> {
    let (mode, raw_slot) = if let Some(raw_slot) = path.strip_prefix("/block/") {
        (RouteBlockMode::Full, raw_slot)
    } else if let Some(raw_slot) = path.strip_prefix("/block-lite/") {
        (RouteBlockMode::Lite, raw_slot)
    } else {
        return None;
    };
    (!raw_slot.is_empty() && !raw_slot.contains('/')).then_some((mode, raw_slot))
}

fn direct_transport(raw_slot: &str) -> &'static str {
    if raw_slot.ends_with(".compact") {
        "http_compact"
    } else if raw_slot.ends_with(".bin") && !raw_slot.ends_with(".proto.bin") {
        "http_binary"
    } else if !raw_slot.contains('.') || raw_slot.ends_with(".json") {
        "http_json"
    } else {
        "unknown"
    }
}

fn archive_cache_generation(env: &worker::Env) -> String {
    // A source switch or a repaired publication must not reuse old bytes.
    let fields = [
        "BZ_ARCHIVE_SOURCE",
        "BZ_ARCHIVE_PREFIX",
        "BZ_ARCHIVE_GENERATION",
        "BZ_ARCHIVE_LAYOUT",
        "BZ_SLOT_INDEX",
        "BZ_R2_BUCKET_BINDING",
        "BZ_S3_ENDPOINT",
        "BZ_S3_BUCKET",
        "BZ_MESSAGE_SCHEMA_OVERRIDES",
        "BZ_METADATA_SCHEMA",
        "BZ_RESOLUTION_PREFIX",
        "BZ_RESOLUTION_GENERATION",
        "BZ_RESOLUTION_BUCKET_BINDING",
        "BZ_RESOLUTION_SLOTS",
        "BZ_LOCATOR_SECRET",
        "BZ_NATIVE_READER_URL",
        "BZ_NATIVE_READER_SECRET",
        "BZ_SLOT_BUNDLE_PREFIX",
        "BZ_SLOT_BUNDLE_GENERATION",
        "BZ_SLOT_BUNDLE_BUCKET_BINDING",
        "BZ_SLOT_BUNDLE_MANIFEST",
        "BZ_FOUNDATION_LOOKUP_URL",
        "BZ_FOUNDATION_LOOKUP_SECRET",
        "BZ_FOUNDATION_LOOKUP_GENERATION",
        "BZ_FOUNDATION_BINARY_RESOLVE_MODE",
        "BZ_FOUNDATION_LOOKUP_MODE",
        "BZ_FOUNDATION_LOOKUP_TIMEOUT_MS",
        "BZ_FOUNDATION_LOOKUP_BODY_TIMEOUT_MS",
    ];
    let identity = fields
        .iter()
        .map(|field| format!("{field}={}", optional_var(env, field).unwrap_or_default()))
        .collect::<Vec<_>>()
        .join("\0");
    api_key_digest(&format!("direct-render-v4-base64\0{identity}"))
}

fn canonical_block_cache_key(
    req: &Request,
    request: BlockRequest,
    mode: RouteBlockMode,
    access_mode: BlockBinAccessMode,
    generation: &str,
) -> Result<String> {
    let mut url = req.url()?;
    url.set_query(None);
    let variant = match request.format {
        BlockResponseFormat::Json => DirectCacheVariant::Json {
            lite: mode == RouteBlockMode::Lite,
            include_rewards: request.include_rewards,
        },
        BlockResponseFormat::Wincode => DirectCacheVariant::Binary {
            include_access: access_mode == BlockBinAccessMode::Include,
        },
    };
    let identity = direct_cache_identity(generation, request.slot, variant);
    url.set_path(&identity.path);
    url.query_pairs_mut()
        .append_pair(identity.query_name, identity.query_value);
    Ok(url.to_string())
}

async fn handle_info(_req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let get_only = optional_var(&ctx.env, "BZ_HTTP_GET_ONLY").as_deref() == Some("true");
    let mut info = json!({
        "ok": true,
        "name": "blockzilla-get-block",
        "authentication": "Authorization: Bearer <api-key>",
        "auth_check_cache": {
            "enabled": optional_var(&ctx.env, "BZ_AUTH_CACHE_SCOPE").is_some_and(|scope| auth_check_cache_key(&scope, "").is_some()),
            "max_added_staleness_ms": AUTH_CHECK_TTL_MS,
            "kv_consistency": "KV propagation delay is additional",
        },
        "profile_modes": {
            "1": "bypass response, index, source-range and auth caches",
            "source": "bypass response and source-range caches; retain index and auth caches",
        },
        "recommended": "GET /block/:slot.bin",
        "json_compatibility": ["GET /block/:slot.json", "GET /block-lite/:slot.json"],
        "methods": if get_only { vec!["GET"] } else { vec!["GET", "POST"] },
        "json_rpc": { "route": "GET /block/:slot.json", "id": 1, "method": "getBlock", "transaction_encoding": "base64", "supported_transaction_encodings": ["base64"] },
        "binary_formats": { ".bin": "Blockzilla getBlock Wincode bundle", ".proto.bin": "not implemented" },
        "archive_source": "compact-v2",
        "archive_backends": ["r2", "s3"],
    });
    if !get_only {
        info["transaction_rpc"] = json!({ "route": "POST /", "method": "getTransaction", "encodings": ["json", "base64", "base58"] });
    }
    if let Some(generation) = optional_var(&ctx.env, "BZ_RESOLUTION_GENERATION") {
        info["slot_resolution"] = json!({
            "route": "GET /block/:slot.resolution",
            "generation": generation,
            "admitted_slots": optional_var(&ctx.env, "BZ_RESOLUTION_SLOTS").unwrap_or_default(),
            "client_binary": "GET /block/:slot.bin?access=client&locator=<X-Blockzilla-Locator>",
            "client_binary_format": "BZPART2! header, compressed hot block, original signatures",
            "required_parent_fields": ["parent_slot", "blockhash", "previous_blockhash"],
        });
    }
    cached_json_response(&info, INFO_CACHE_CONTROL)
}

#[derive(Clone, Copy)]
struct BlockRequest {
    slot: u64,
    format: BlockResponseFormat,
    include_rewards: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BlockResponseFormat {
    Json,
    Wincode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockBinAccessMode {
    Include,
    Skip,
}

impl BlockBinAccessMode {
    fn cache_key_suffix(self) -> &'static str {
        match self {
            Self::Include => "access",
            Self::Skip => "no-access",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RouteBlockMode {
    Full,
    Lite,
}

impl RouteBlockMode {
    fn metric_method(self) -> &'static str {
        match self {
            Self::Full => "getBlock",
            Self::Lite => "getBlockLite",
        }
    }
}

fn parse_block_request(
    req: &Request,
    raw_slot: &str,
) -> std::result::Result<BlockRequest, Response> {
    let (slot_text, format) = parse_slot_and_format(raw_slot)?;
    let slot = slot_text.parse().map_err(|_| invalid_slot_response())?;
    if format == BlockResponseFormat::Json
        && req
            .url()
            .map_err(|_| invalid_slot_response())?
            .query_pairs()
            .any(|(key, value)| key == "encoding" && value != "base64")
    {
        return Err(json_error(
            400,
            "unsupported_encoding",
            "Only base64 transaction encoding is supported",
        )
        .unwrap_or_else(|_| Response::error("Unsupported encoding", 400).unwrap()));
    }
    let include_rewards = if format == BlockResponseFormat::Json {
        parse_include_rewards(req)?
    } else {
        true
    };
    Ok(BlockRequest {
        slot,
        format,
        include_rewards,
    })
}

fn parse_slot_and_format(
    raw_slot: &str,
) -> std::result::Result<(&str, BlockResponseFormat), Response> {
    if raw_slot.ends_with(".proto.bin") {
        return Err(json_error(
            400,
            "unsupported_format",
            "protobuf block responses are not implemented; use .bin or .json",
        )
        .unwrap_or_else(|_| Response::error("Unsupported format", 400).unwrap()));
    }
    if raw_slot.ends_with(".zstd") {
        return Err(json_error(
            400,
            "unsupported_format",
            "zstd block responses are not supported; use .json or .bin",
        )
        .unwrap_or_else(|_| Response::error("Unsupported format", 400).unwrap()));
    }
    if let Some(slot) = raw_slot.strip_suffix(".json") {
        return Ok((slot, BlockResponseFormat::Json));
    }
    if let Some(slot) = raw_slot.strip_suffix(".bin") {
        return Ok((slot, BlockResponseFormat::Wincode));
    }
    if raw_slot.contains('.') {
        return Err(json_error(
            400,
            "unsupported_format",
            "unsupported block response extension; use .json, .bin, or .proto.bin",
        )
        .unwrap_or_else(|_| Response::error("Unsupported format", 400).unwrap()));
    }

    Ok((raw_slot, BlockResponseFormat::Json))
}

fn block_bin_access_mode(req: &Request) -> BlockBinAccessMode {
    let skip_access = req.url().ok().is_some_and(|url| {
        url.query_pairs().any(|(key, value)| {
            let key = key.as_ref();
            let value = value.as_ref();
            (matches!(key, "access" | "includeAccess")
                && matches!(value, "0" | "false" | "no" | "none" | "skip"))
                || (matches!(key, "noAccess" | "skipAccess")
                    && matches!(value, "" | "1" | "true" | "yes"))
        })
    });
    if skip_access {
        BlockBinAccessMode::Skip
    } else {
        BlockBinAccessMode::Include
    }
}

fn parse_include_rewards(req: &Request) -> std::result::Result<bool, Response> {
    let url = req
        .url()
        .map_err(|_| Response::error("Invalid request URL", 400).unwrap())?;
    let mut include_rewards = true;
    for (key, value) in url.query_pairs() {
        if key == "rewards" || key == "includeRewards" || key == "include_rewards" {
            include_rewards = parse_bool_query_value(&value).ok_or_else(|| {
                json_error(
                    400,
                    "invalid_rewards",
                    "rewards must be true/false, 1/0, yes/no, or on/off",
                )
                .unwrap_or_else(|_| Response::error("Invalid rewards flag", 400).unwrap())
            })?;
        }
    }
    Ok(include_rewards)
}

fn parse_bool_query_value(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn invalid_slot_response() -> Response {
    json_error(400, "invalid_slot", "slot must be an unsigned integer")
        .unwrap_or_else(|_| Response::error("Invalid slot", 400).unwrap())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RpcRequest {
    jsonrpc: Option<String>,
    id: Option<Value>,
    method: Option<String>,
    params: Option<Value>,
}

#[derive(Debug)]
struct RpcError {
    code: i64,
    message: String,
}

impl RpcError {
    fn invalid_params(message: impl Into<String>) -> Self {
        Self {
            code: -32602,
            message: message.into(),
        }
    }

    fn method_not_found(method: &str) -> Self {
        Self {
            code: -32601,
            message: format!("Method not found: {method}"),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            code: -32000,
            message: message.into(),
        }
    }

    fn skipped_slot(slot: u64) -> Self {
        Self {
            code: -32009,
            message: format!("Slot {slot} was skipped, or missing in long-term storage"),
        }
    }
}

struct RpcExecution {
    response: Response,
    method: &'static str,
    outcome: &'static str,
    request_bytes: usize,
    billable_backend_reads: u8,
    storage: StorageSnapshot,
}

enum RpcBodyReadError {
    TooLarge,
    Read,
}

async fn handle_rpc(mut req: Request, env: worker::Env) -> Result<Response> {
    let request_started = now_ms();
    let profile = request_profile(&req);
    let api_key = match authenticate_api_request(&req, &env).await {
        Ok(record) => record,
        Err(RpcAuthError::Unauthorized) => return api_unauthorized_response(),
        Err(RpcAuthError::Unavailable) => {
            return json_error_profiled(
                503,
                "rpc_unavailable",
                "RPC authentication is temporarily unavailable",
                profile.as_ref(),
            );
        }
    };
    let metrics = match rpc_metrics(&env, profile.as_ref()) {
        Ok(metrics) => metrics,
        Err(response) => return Ok(response),
    };

    let body_started = now_ms();
    let body = match read_rpc_body(&mut req).await {
        Ok(body) => body,
        Err(RpcBodyReadError::TooLarge) => {
            let execution = RpcExecution {
                response: json_error_profiled(
                    413,
                    "request_too_large",
                    "JSON-RPC request bodies are limited to 1 MiB",
                    profile.as_ref(),
                )?,
                method: "invalid",
                outcome: "request_too_large",
                request_bytes: RPC_REQUEST_BODY_MAX_BYTES,
                billable_backend_reads: 0,
                storage: StorageSnapshot::default(),
            };
            return finish_metered_rpc(
                execution,
                &api_key,
                &metrics,
                request_started,
                profile.as_ref(),
            );
        }
        Err(RpcBodyReadError::Read) => {
            let execution = RpcExecution {
                response: json_error_profiled(
                    400,
                    "invalid_request_body",
                    "Could not read the JSON-RPC request body",
                    profile.as_ref(),
                )?,
                method: "invalid",
                outcome: "body_read_error",
                request_bytes: 0,
                billable_backend_reads: 0,
                storage: StorageSnapshot::default(),
            };
            return finish_metered_rpc(
                execution,
                &api_key,
                &metrics,
                request_started,
                profile.as_ref(),
            );
        }
    };

    if let Some(profile) = profile.as_ref() {
        profile.record_elapsed(
            "request_body",
            body_started,
            body.len() as u64,
            "json_rpc",
            None,
        );
    }
    let rpc_started = now_ms();
    let request_bytes = body.len();
    let execution = match execute_rpc_body(body, &env, profile.clone(), rpc_started).await {
        Ok(execution) => execution,
        Err(err) => {
            console_error!(
                "{}",
                json!({
                    "event": "rpc_request_error",
                    "keyId": api_key.key_id.as_str(),
                    "error": err.to_string(),
                })
            );
            RpcExecution {
                response: json_error_profiled(
                    500,
                    "internal_error",
                    "The JSON-RPC request could not be completed",
                    profile.as_ref(),
                )?,
                method: "invalid",
                outcome: "internal_error",
                request_bytes,
                billable_backend_reads: 0,
                storage: StorageSnapshot::default(),
            }
        }
    };

    finish_metered_rpc(
        execution,
        &api_key,
        &metrics,
        request_started,
        profile.as_ref(),
    )
}

async fn execute_rpc_body(
    body: Vec<u8>,
    env: &worker::Env,
    profile: Option<ProfileHandle>,
    rpc_started: f64,
) -> Result<RpcExecution> {
    let request_bytes = body.len();
    let parsed = serde_json::from_slice::<Value>(&body);
    let method = parsed
        .as_ref()
        .map(rpc_method_for_metrics)
        .unwrap_or("invalid");
    let value = match parsed {
        Ok(value) => value,
        Err(err) => {
            if let Some(profile) = profile.as_ref() {
                profile.record_elapsed("rpc_total", rpc_started, 0, "parse_error", None);
            }
            return Ok(RpcExecution {
                response: json_rpc_response_profiled(
                    error_response(Value::Null, -32700, err.to_string()),
                    profile.as_ref(),
                )?,
                method,
                outcome: "parse_error",
                request_bytes,
                billable_backend_reads: 0,
                storage: StorageSnapshot::default(),
            });
        }
    };

    if value.is_array() {
        if let Some(profile) = profile.as_ref() {
            profile.record_elapsed("rpc_total", rpc_started, 0, "batch_rejected", None);
        }
        return Ok(RpcExecution {
            response: json_rpc_response_profiled(
                error_response(
                    Value::Null,
                    -32600,
                    "JSON-RPC batch requests are not supported; submit one request per HTTP call for predictable pricing",
                ),
                profile.as_ref(),
            )?,
            method,
            outcome: "batch_rejected",
            request_bytes,
            billable_backend_reads: 0,
            storage: StorageSnapshot::default(),
        });
    }

    // POST is reserved for getTransaction. Block requests retain their GET
    // transport and cache contract.
    if let Some(other) = value
        .get("method")
        .and_then(Value::as_str)
        .filter(|method| *method != "getTransaction")
    {
        return Ok(RpcExecution {
            response: json_rpc_response_profiled(
                error_response(
                    value.get("id").cloned().unwrap_or(Value::Null),
                    -32601,
                    format!("Method not found: {other}"),
                ),
                profile.as_ref(),
            )?,
            method,
            outcome: "rpc_error",
            request_bytes,
            billable_backend_reads: 0,
            storage: StorageSnapshot::default(),
        });
    }
    if let Some(local_response) = local_rpc_response(&value) {
        let outcome = if local_response.get("error").is_some() {
            "rpc_error"
        } else {
            "ok"
        };
        if let Some(profile) = profile.as_ref() {
            profile.record_elapsed("rpc_total", rpc_started, 0, "local", None);
        }
        return Ok(RpcExecution {
            response: json_rpc_response_profiled(local_response, profile.as_ref())?,
            method,
            outcome,
            request_bytes,
            billable_backend_reads: 0,
            storage: StorageSnapshot::default(),
        });
    }

    let source = match WorkerSource::from_env(env, profile.clone()) {
        Ok(source) => source,
        Err(err) => {
            if let Some(profile) = profile.as_ref() {
                profile.record_elapsed("rpc_total", rpc_started, 0, "config_error", None);
            }
            return Ok(RpcExecution {
                response: json_rpc_response_profiled(
                    error_response(Value::Null, -32000, err),
                    profile.as_ref(),
                )?,
                method,
                outcome: "config_error",
                request_bytes,
                billable_backend_reads: 0,
                storage: StorageSnapshot::default(),
            });
        }
    };

    match handle_one_streamed(&source, &value).await {
        Ok(Some(StreamedRpcBody::Buffered(bytes))) => {
            source.record_elapsed(
                "rpc_total",
                rpc_started,
                bytes.len() as u64,
                "single_streamed",
                None,
            );
            return Ok(RpcExecution {
                response: json_bytes_response_profiled(
                    bytes,
                    ERROR_CACHE_CONTROL,
                    profile.as_ref(),
                )?,
                method,
                outcome: "ok",
                request_bytes,
                billable_backend_reads: source.billable_backend_reads(),
                storage: source.storage_metrics.snapshot(),
            });
        }
        Ok(Some(StreamedRpcBody::Stream(body))) => {
            source.record_elapsed("rpc_total", rpc_started, 0, "single_stream_body", None);
            return Ok(RpcExecution {
                response: json_stream_response_profiled(
                    body,
                    ERROR_CACHE_CONTROL,
                    profile.as_ref(),
                )?,
                method,
                outcome: "ok",
                request_bytes,
                billable_backend_reads: source.billable_backend_reads(),
                storage: source.storage_metrics.snapshot(),
            });
        }
        Ok(None) => {}
        Err(response) => {
            source.record_elapsed("rpc_total", rpc_started, 0, "single_streamed_error", None);
            return Ok(RpcExecution {
                response: json_rpc_response_profiled(response, profile.as_ref())?,
                method,
                outcome: "rpc_error",
                request_bytes,
                billable_backend_reads: source.billable_backend_reads(),
                storage: source.storage_metrics.snapshot(),
            });
        }
    }

    let value = handle_one(&source, value).await;
    let outcome = if value.get("error").is_some() {
        "rpc_error"
    } else {
        "ok"
    };
    source.record_elapsed("rpc_total", rpc_started, 0, "single", None);
    Ok(RpcExecution {
        response: json_rpc_response_profiled(value, profile.as_ref())?,
        method,
        outcome,
        request_bytes,
        billable_backend_reads: source.billable_backend_reads(),
        storage: source.storage_metrics.snapshot(),
    })
}

// Return a complete local response when the request cannot or should not
// touch archive storage. `None` is reserved for a fully validated archive
// method, so only that path needs WorkerSource configuration.
fn local_rpc_response(value: &Value) -> Option<Value> {
    let request: RpcRequest = match serde_json::from_value(value.clone()) {
        Ok(request) => request,
        Err(err) => return Some(error_response(Value::Null, -32600, err.to_string())),
    };
    let id = request.id.clone().unwrap_or(Value::Null);
    if request.jsonrpc.as_deref() != Some("2.0") {
        return Some(error_response(
            id,
            -32600,
            "Invalid Request: jsonrpc must be \"2.0\"",
        ));
    }
    let Some(method) = request.method.as_deref() else {
        return Some(error_response(
            id,
            -32600,
            "Invalid Request: missing method",
        ));
    };
    if request.params.as_ref().is_some_and(contains_json_parsed) {
        return Some(error_response(
            id,
            -32602,
            "The jsonParsed encoding is not supported by this archive RPC",
        ));
    }

    let validation = match method {
        "getTransaction" => crate::transaction_rpc::parse_params(request.params.as_ref())
            .map(|_| ())
            .map_err(|error| RpcError {
                code: error.code,
                message: error.message,
            }),
        "getBlock" => get_block_params(&request).map(|_| ()),
        "getBlockTime" => params_array(&request).and_then(|params| {
            params
                .first()
                .and_then(Value::as_u64)
                .map(|_| ())
                .ok_or_else(|| {
                    RpcError::invalid_params("getBlockTime requires slot as first parameter")
                })
        }),
        "getVersion" => {
            return Some(success_response(
                id,
                json!({
                    "solana-core": concat!("blockzilla-get-block/", env!("CARGO_PKG_VERSION"))
                }),
            ));
        }
        _ => {
            return Some(error_response(
                id,
                -32601,
                format!("Method not found: {method}"),
            ));
        }
    };

    match validation {
        Ok(()) => None,
        Err(err) => Some(error_response(id, err.code, err.message)),
    }
}

const AUTH_CHECK_TTL_MS: f64 = 5_000.0;
const AUTH_CHECK_MAX_ENTRIES: usize = 256;
const AUTH_CHECK_MAX_BYTES: usize = 128 * 1024;
const AUTH_EDGE_MAX_BODY_BYTES: usize = 1024;

struct AuthCheckEntry {
    scope_digest: String,
    record: RpcApiKeyRecord,
    checked_at_ms: f64,
    expires_at_ms: f64,
    payload_bytes: usize,
}

/// Only completed, validated positive records enter this private isolate cache.
/// Expiry is not extended on hits. It adds at most five seconds to the
/// staleness of a KV observation; KV propagation is a separate constraint.
struct AuthCheckCache {
    entries: std::collections::VecDeque<AuthCheckEntry>,
    payload_bytes: usize,
    entry_limit: usize,
    byte_limit: usize,
}

impl AuthCheckCache {
    fn new(entry_limit: usize, byte_limit: usize) -> Self {
        let entry_limit = entry_limit.min(
            byte_limit.saturating_sub(std::mem::size_of::<Self>())
                / std::mem::size_of::<AuthCheckEntry>(),
        );
        Self {
            entries: std::collections::VecDeque::with_capacity(entry_limit),
            payload_bytes: 0,
            entry_limit,
            byte_limit,
        }
    }

    fn allocated_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(
                self.entries
                    .capacity()
                    .saturating_mul(std::mem::size_of::<AuthCheckEntry>()),
            )
            .saturating_add(self.payload_bytes)
    }

    fn prune(&mut self, now: f64) {
        self.entries.retain(|entry| {
            now.is_finite() && now >= entry.checked_at_ms && now < entry.expires_at_ms
        });
        self.payload_bytes = self.entries.iter().map(|entry| entry.payload_bytes).sum();
    }

    fn get(&mut self, scope_digest: &str, now: f64) -> Option<RpcApiKeyRecord> {
        self.prune(now);
        let index = self
            .entries
            .iter()
            .position(|entry| entry.scope_digest == scope_digest)?;
        let entry = self.entries.remove(index)?;
        let record = entry.record.clone();
        self.entries.push_back(entry);
        Some(record)
    }

    fn insert_completed(
        &mut self,
        scope_digest: String,
        record: &RpcApiKeyRecord,
        checked_at_ms: f64,
        completed_at_ms: f64,
    ) {
        self.prune(completed_at_ms);
        let expires_at_ms = checked_at_ms + AUTH_CHECK_TTL_MS;
        if self.entry_limit == 0
            || !checked_at_ms.is_finite()
            || !completed_at_ms.is_finite()
            || !expires_at_ms.is_finite()
            || completed_at_ms < checked_at_ms
            || completed_at_ms >= expires_at_ms
            || record.validate().is_err()
            || !record.is_enabled()
        {
            return;
        }
        let record = record.clone();
        let payload_bytes = scope_digest
            .capacity()
            .saturating_add(record.key_id.capacity())
            .saturating_add(record.customer_id.capacity())
            .saturating_add(record.label.capacity());
        if let Some(index) = self
            .entries
            .iter()
            .position(|entry| entry.scope_digest == scope_digest)
        {
            if let Some(old) = self.entries.remove(index) {
                self.payload_bytes -= old.payload_bytes;
            }
        }
        while !self.entries.is_empty()
            && (self.entries.len() >= self.entry_limit
                || self.allocated_bytes().saturating_add(payload_bytes) > self.byte_limit)
        {
            if let Some(old) = self.entries.pop_front() {
                self.payload_bytes -= old.payload_bytes;
            }
        }
        if self.allocated_bytes().saturating_add(payload_bytes) > self.byte_limit {
            return;
        }
        self.payload_bytes += payload_bytes;
        self.entries.push_back(AuthCheckEntry {
            scope_digest,
            record,
            checked_at_ms,
            expires_at_ms,
            payload_bytes,
        });
    }
}

thread_local! {
    // No API key, binding object, request, response, stream, or pending I/O is retained.
    static AUTH_CHECKS: RefCell<AuthCheckCache> = RefCell::new(AuthCheckCache::new(AUTH_CHECK_MAX_ENTRIES, AUTH_CHECK_MAX_BYTES));
}

fn auth_check_cache_key(scope: &str, key_digest: &str) -> Option<String> {
    if scope.is_empty() || scope.len() > 128 || scope.chars().any(char::is_control) {
        return None;
    }
    Some(api_key_digest(&format!(
        "auth-check-v1\0{RPC_API_KEYS_BINDING}\0{scope}\0{key_digest}"
    )))
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AuthEdgeEnvelope {
    version: u8,
    origin_digest: String,
    scope_digest: String,
    key_digest: String,
    checked_at_utc_ms: f64,
    record: RpcApiKeyRecord,
}

struct AuthEdgeHit {
    record: RpcApiKeyRecord,
    checked_at_utc_ms: f64,
}

#[cfg(target_arch = "wasm32")]
fn auth_check_utc_ms() -> f64 {
    js_sys::Date::now()
}

#[cfg(not(target_arch = "wasm32"))]
fn auth_check_utc_ms() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_millis() as f64)
        .unwrap_or(f64::NAN)
}

fn auth_digest_is_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn auth_edge_cache_key(origin: &str, scope_digest: &str) -> Option<String> {
    if origin.len() > 512 || !auth_digest_is_valid(scope_digest) {
        return None;
    }
    let url = worker::Url::parse(origin).ok()?;
    if !matches!(url.scheme(), "http" | "https") || url.origin().ascii_serialization() != origin {
        return None;
    }
    Some(format!(
        "{origin}/__blockzilla-auth-positive/v1/{scope_digest}"
    ))
}

fn auth_edge_remaining_ttl_ms(checked_at_utc_ms: f64, now_utc_ms: f64) -> Option<f64> {
    if !checked_at_utc_ms.is_finite()
        || !now_utc_ms.is_finite()
        || checked_at_utc_ms < 0.0
        || checked_at_utc_ms.fract() != 0.0
        || checked_at_utc_ms > 9_007_199_254_740_991.0
        || now_utc_ms < checked_at_utc_ms
    {
        return None;
    }
    let remaining = AUTH_CHECK_TTL_MS - (now_utc_ms - checked_at_utc_ms);
    (remaining > 0.0 && remaining <= AUTH_CHECK_TTL_MS).then_some(remaining)
}

fn validate_auth_edge_envelope(
    bytes: &[u8],
    origin: &str,
    scope_digest: &str,
    key_digest: &str,
    now_utc_ms: f64,
) -> Option<AuthEdgeHit> {
    if bytes.is_empty()
        || bytes.len() > AUTH_EDGE_MAX_BODY_BYTES
        || !auth_digest_is_valid(scope_digest)
        || !auth_digest_is_valid(key_digest)
    {
        return None;
    }
    let envelope: AuthEdgeEnvelope = serde_json::from_slice(bytes).ok()?;
    if envelope.version != 1
        || envelope.origin_digest != api_key_digest(origin)
        || envelope.scope_digest != scope_digest
        || envelope.key_digest != key_digest
        || envelope.record.validate().is_err()
        || !envelope.record.is_enabled()
    {
        return None;
    }
    auth_edge_remaining_ttl_ms(envelope.checked_at_utc_ms, now_utc_ms)?;
    Some(AuthEdgeHit {
        checked_at_utc_ms: envelope.checked_at_utc_ms,
        record: envelope.record,
    })
}

fn encode_auth_edge_envelope(
    origin: &str,
    scope_digest: &str,
    key_digest: &str,
    record: &RpcApiKeyRecord,
    checked_at_utc_ms: f64,
    now_utc_ms: f64,
) -> Option<(Vec<u8>, u32)> {
    if !auth_digest_is_valid(scope_digest)
        || !auth_digest_is_valid(key_digest)
        || record.validate().is_err()
        || !record.is_enabled()
    {
        return None;
    }
    let remaining = auth_edge_remaining_ttl_ms(checked_at_utc_ms, now_utc_ms)?;
    let bytes = serde_json::to_vec(&AuthEdgeEnvelope {
        version: 1,
        origin_digest: api_key_digest(origin),
        scope_digest: scope_digest.into(),
        key_digest: key_digest.into(),
        checked_at_utc_ms,
        record: record.clone(),
    })
    .ok()?;
    if bytes.len() > AUTH_EDGE_MAX_BODY_BYTES {
        return None;
    }
    // Cache TTL has whole-second precision. The embedded UTC deadline is
    // authoritative, including after a slow cache publication.
    Some((bytes, (remaining / 1000.0).ceil() as u32))
}

fn promote_auth_edge_hit(
    cache: &mut AuthCheckCache,
    scope_digest: String,
    hit: &AuthEdgeHit,
    local_now_ms: f64,
    utc_now_ms: f64,
) -> bool {
    // Recompute at promotion; time spent since envelope validation is not free.
    let Some(remaining_ttl_ms) = auth_edge_remaining_ttl_ms(hit.checked_at_utc_ms, utc_now_ms)
    else {
        return false;
    };
    // A fresh runtime can have local_now_ms smaller than the record's age.
    // A negative local anchor is valid; insert_completed preserves its deadline.
    let local_checked_ms = local_now_ms - (AUTH_CHECK_TTL_MS - remaining_ttl_ms);
    cache.insert_completed(scope_digest, &hit.record, local_checked_ms, local_now_ms);
    true
}

async fn read_auth_edge(
    cache_url: &str,
    origin: &str,
    scope_digest: &str,
    key_digest: &str,
) -> Option<AuthEdgeHit> {
    let mut response = Cache::default()
        .get(cache_url.to_string(), false)
        .await
        .ok()??;
    if response.status_code() != 200 {
        return None;
    }
    let declared = response
        .headers()
        .get("Content-Length")
        .ok()??
        .parse::<usize>()
        .ok()
        .filter(|length| (1..=AUTH_EDGE_MAX_BODY_BYTES).contains(length))?;
    let mut bytes = Vec::with_capacity(declared);
    let mut stream = response.stream().ok()?;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.ok()?;
        if bytes.len().saturating_add(chunk.len()) > declared {
            return None;
        }
        bytes.extend_from_slice(&chunk);
    }
    if bytes.len() != declared {
        return None;
    }
    validate_auth_edge_envelope(
        &bytes,
        origin,
        scope_digest,
        key_digest,
        auth_check_utc_ms(),
    )
}

async fn publish_auth_edge(
    cache_url: &str,
    origin: &str,
    scope_digest: &str,
    key_digest: &str,
    record: &RpcApiKeyRecord,
    checked_at_utc_ms: f64,
) {
    let Some((bytes, ttl_seconds)) = encode_auth_edge_envelope(
        origin,
        scope_digest,
        key_digest,
        record,
        checked_at_utc_ms,
        auth_check_utc_ms(),
    ) else {
        return;
    };
    let length = bytes.len();
    let Ok(mut response) = Response::from_bytes(bytes) else {
        return;
    };
    if response
        .headers_mut()
        .set("Content-Type", "application/json")
        .is_err()
        || response
            .headers_mut()
            .set("Content-Length", &length.to_string())
            .is_err()
        || response
            .headers_mut()
            .set("Cache-Control", &format!("public, max-age={ttl_seconds}"))
            .is_err()
    {
        return;
    }
    // A cache outage must never invalidate a successful KV observation.
    let _ = Cache::default().put(cache_url.to_string(), response).await;
}

struct AuthenticatedApiKey {
    record: RpcApiKeyRecord,
    cache_status: &'static str,
    cache_tier: &'static str,
}

enum RpcAuthError {
    Unauthorized,
    Unavailable,
}

async fn authenticate_api_request(
    req: &Request,
    env: &worker::Env,
) -> std::result::Result<RpcApiKeyRecord, RpcAuthError> {
    // Keep the existing POST/getTransaction contract: each call reads KV.
    authenticate_api_key_with_cache_policy(req, env, false)
        .await
        .map(|authenticated| authenticated.record)
}

async fn authenticate_api_key_with_cache_policy(
    req: &Request,
    env: &worker::Env,
    allow_cache: bool,
) -> std::result::Result<AuthenticatedApiKey, RpcAuthError> {
    let authorization = req
        .headers()
        .get("Authorization")
        .map_err(|_| RpcAuthError::Unauthorized)?;
    let key = parse_bearer_key(authorization.as_deref()).map_err(|_| RpcAuthError::Unauthorized)?;
    let digest = api_key_digest(key);
    let keys = env.kv(RPC_API_KEYS_BINDING).map_err(|_| {
        console_error!(
            "{}",
            json!({
                "event": "rpc_auth_backend_error",
                "reason": "missing_binding",
            })
        );
        RpcAuthError::Unavailable
    })?;
    let cache_key = allow_cache
        .then(|| optional_var(env, "BZ_AUTH_CACHE_SCOPE"))
        .flatten()
        .and_then(|scope| auth_check_cache_key(&scope, &digest));
    if let Some(cache_key) = &cache_key {
        if let Some(record) = AUTH_CHECKS.with(|cache| cache.borrow_mut().get(cache_key, now_ms()))
        {
            return Ok(AuthenticatedApiKey {
                record,
                cache_status: "hit",
                cache_tier: "memory",
            });
        }
    }
    let edge = cache_key.as_ref().and_then(|scope_digest| {
        let origin = req.url().ok()?.origin().ascii_serialization();
        Some((auth_edge_cache_key(&origin, scope_digest)?, origin))
    });
    if let (Some(scope_digest), Some((cache_url, origin))) = (&cache_key, &edge) {
        if let Some(hit) = read_auth_edge(cache_url, origin, scope_digest, &digest).await {
            // Sample the local clock first so conversion is conservative if
            // local timers advance between the two observations.
            let local_now_ms = now_ms();
            let utc_now_ms = auth_check_utc_ms();
            let fresh = AUTH_CHECKS.with(|cache| {
                promote_auth_edge_hit(
                    &mut cache.borrow_mut(),
                    scope_digest.clone(),
                    &hit,
                    local_now_ms,
                    utc_now_ms,
                )
            });
            if fresh {
                return Ok(AuthenticatedApiKey {
                    record: hit.record,
                    cache_status: "hit",
                    cache_tier: "edge",
                });
            }
        }
    }
    // Count the TTL from read start, so a slow KV read cannot extend it.
    let checked_at_ms = now_ms();
    let checked_at_utc_ms = auth_check_utc_ms();
    let record = keys
        .get(&digest)
        .json::<RpcApiKeyRecord>()
        .await
        .map_err(|_| {
            console_error!(
                "{}",
                json!({
                    "event": "rpc_auth_backend_error",
                    "reason": "kv_read",
                })
            );
            RpcAuthError::Unavailable
        })?
        .ok_or(RpcAuthError::Unauthorized)?;
    if let Err(reason) = record.validate() {
        console_error!(
            "{}",
            json!({
                "event": "rpc_auth_backend_error",
                "reason": "invalid_record",
                "detail": reason,
            })
        );
        return Err(RpcAuthError::Unavailable);
    }
    if !record.is_enabled() {
        return Err(RpcAuthError::Unauthorized);
    }
    if let (Some(scope_digest), Some((cache_url, origin))) = (&cache_key, &edge) {
        // Await publication so a completed warmup is available to other isolates.
        publish_auth_edge(
            cache_url,
            origin,
            scope_digest,
            &digest,
            &record,
            checked_at_utc_ms,
        )
        .await;
    }
    let cache_status = if let Some(cache_key) = cache_key {
        AUTH_CHECKS.with(|cache| {
            cache
                .borrow_mut()
                .insert_completed(cache_key, &record, checked_at_ms, now_ms());
        });
        "miss"
    } else {
        "bypass"
    };
    Ok(AuthenticatedApiKey {
        record,
        cache_status,
        cache_tier: if cache_status == "bypass" {
            "bypass"
        } else {
            "kv"
        },
    })
}

#[cfg(test)]
mod auth_check_cache_tests {
    use super::*;
    use crate::rpc_access::RpcApiKeyStatus;

    fn enabled() -> RpcApiKeyRecord {
        RpcApiKeyRecord {
            key_id: "key_test".into(),
            customer_id: "customer_test".into(),
            label: "Private test record".into(),
            status: RpcApiKeyStatus::Enabled,
        }
    }

    #[test]
    fn expires_at_five_seconds_without_sliding_on_hits() {
        let mut cache = AuthCheckCache::new(2, 4096);
        cache.insert_completed("digest".into(), &enabled(), 100.0, 200.0);
        assert_eq!(cache.get("digest", 200.0), Some(enabled()));
        assert_eq!(cache.get("digest", 5099.0), Some(enabled()));
        assert_eq!(cache.get("digest", 5100.0), None);
        assert!(cache.entries.is_empty());
    }

    #[test]
    fn completed_slow_reads_do_not_extend_the_check_deadline() {
        let mut cache = AuthCheckCache::new(2, 4096);
        cache.insert_completed("late".into(), &enabled(), 100.0, 5100.0);
        assert!(cache.get("late", 5100.0).is_none());
        cache.insert_completed("nearly_late".into(), &enabled(), 100.0, 5099.0);
        assert!(cache.get("nearly_late", 5099.0).is_some());
        assert!(cache.get("nearly_late", 5100.0).is_none());
    }

    #[test]
    fn failures_invalid_records_and_invalid_clocks_never_enter_cache() {
        let mut cache = AuthCheckCache::new(2, 4096);
        let mut disabled = enabled();
        disabled.status = RpcApiKeyStatus::Disabled;
        cache.insert_completed("disabled".into(), &disabled, 0.0, 1.0);
        let mut invalid = enabled();
        invalid.customer_id.clear();
        cache.insert_completed("invalid".into(), &invalid, 0.0, 1.0);
        cache.insert_completed("nan".into(), &enabled(), f64::NAN, 1.0);
        cache.insert_completed("infinite".into(), &enabled(), 0.0, f64::INFINITY);
        cache.insert_completed("backwards".into(), &enabled(), 10.0, 9.0);
        assert!(cache.entries.is_empty());
        cache.insert_completed("valid".into(), &enabled(), 10.0, 10.0);
        assert!(
            cache.get("valid", 9.0).is_none(),
            "clock rollback fails closed"
        );
    }

    #[test]
    fn bounds_entry_count_bytes_and_owned_record_clones() {
        let mut cache = AuthCheckCache::new(2, 4096);
        let mut record = enabled();
        cache.insert_completed("a".into(), &record, 0.0, 0.0);
        record.label = "Changed outside cache".into();
        assert_eq!(cache.get("a", 1.0), Some(enabled()));
        cache.insert_completed("b".into(), &enabled(), 0.0, 1.0);
        cache.get("a", 2.0);
        cache.insert_completed("c".into(), &enabled(), 0.0, 2.0);
        assert!(
            cache.get("b", 2.0).is_none(),
            "least-recent entry is evicted"
        );
        assert_eq!(cache.entries.len(), 2);

        let mut bounded = AuthCheckCache::new(2, 512);
        for index in 0..256 {
            bounded.insert_completed(format!("{index:064x}"), &enabled(), 0.0, 1.0);
            assert!(bounded.allocated_bytes() <= 512);
            assert!(bounded.entries.len() <= 2);
        }
        let mut full = AuthCheckCache::new(AUTH_CHECK_MAX_ENTRIES, AUTH_CHECK_MAX_BYTES);
        for index in 0..1024 {
            full.insert_completed(format!("{index:064x}"), &enabled(), 0.0, 1.0);
            assert!(full.allocated_bytes() <= AUTH_CHECK_MAX_BYTES);
            assert!(full.entries.len() <= AUTH_CHECK_MAX_ENTRIES);
        }
    }

    #[test]
    fn separates_namespace_scopes_without_retaining_the_api_key() {
        let raw = "bz_live_example_private_key_abcdefghijklmnopqrstuvwxyz012345";
        let digest = api_key_digest(raw);
        let first = auth_check_cache_key("namespace_a", &digest).unwrap();
        let second = auth_check_cache_key("namespace_b", &digest).unwrap();
        assert_ne!(first, second);
        assert_eq!(first.len(), 64);
        assert!(!first.contains(raw));
        assert!(!first.contains("namespace_a"));
        assert!(auth_check_cache_key("", &digest).is_none());
        assert!(auth_check_cache_key(&"x".repeat(129), &digest).is_none());
        assert!(auth_check_cache_key("bad\nscope", &digest).is_none());
    }

    #[test]
    fn edge_envelope_rejects_stale_future_disabled_and_wrong_identity() {
        let origin = "https://auth.example";
        let digest = api_key_digest("private fixture key");
        let scope = auth_check_cache_key("namespace_a", &digest).unwrap();
        let (bytes, ttl) =
            encode_auth_edge_envelope(origin, &scope, &digest, &enabled(), 10_000.0, 10_001.0)
                .unwrap();
        assert_eq!(ttl, 5);
        assert!(validate_auth_edge_envelope(&bytes, origin, &scope, &digest, 14_999.0).is_some());
        for now in [9_999.0, 15_000.0, f64::NAN, f64::INFINITY] {
            assert!(validate_auth_edge_envelope(&bytes, origin, &scope, &digest, now).is_none());
        }
        assert!(
            validate_auth_edge_envelope(&bytes, "https://other.example", &scope, &digest, 10_001.0)
                .is_none()
        );
        let wrong = api_key_digest("wrong identity");
        assert!(validate_auth_edge_envelope(&bytes, origin, &wrong, &digest, 10_001.0).is_none());
        assert!(validate_auth_edge_envelope(&bytes, origin, &scope, &wrong, 10_001.0).is_none());
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        for (field, replacement) in [
            ("version", json!(2)),
            ("originDigest", json!(wrong)),
            ("checkedAtUtcMs", json!(10_002)),
            ("unknown", json!(true)),
        ] {
            let mut bad = value.clone();
            bad[field] = replacement;
            assert!(
                validate_auth_edge_envelope(
                    &serde_json::to_vec(&bad).unwrap(),
                    origin,
                    &scope,
                    &digest,
                    10_001.0
                )
                .is_none()
            );
        }
        for (field, replacement) in [("status", json!("disabled")), ("customerId", json!(""))] {
            let mut bad = value.clone();
            bad["record"][field] = replacement;
            assert!(
                validate_auth_edge_envelope(
                    &serde_json::to_vec(&bad).unwrap(),
                    origin,
                    &scope,
                    &digest,
                    10_001.0
                )
                .is_none()
            );
        }
        assert!(
            validate_auth_edge_envelope(b"not JSON", origin, &scope, &digest, 10_001.0).is_none()
        );
        assert!(
            validate_auth_edge_envelope(
                &vec![b' '; AUTH_EDGE_MAX_BODY_BYTES + 1],
                origin,
                &scope,
                &digest,
                10_001.0
            )
            .is_none()
        );
    }

    #[test]
    fn edge_promotion_preserves_deadline_after_delay_in_a_fresh_runtime() {
        let origin = "https://auth.example";
        let digest = api_key_digest("private fixture key");
        let scope = auth_check_cache_key("namespace_a", &digest).unwrap();
        let (bytes, _) =
            encode_auth_edge_envelope(origin, &scope, &digest, &enabled(), 10_000.0, 10_000.0)
                .unwrap();
        let hit = validate_auth_edge_envelope(&bytes, origin, &scope, &digest, 14_000.0).unwrap();
        let mut cache = AuthCheckCache::new(2, 4096);
        // Promotion happens500ms later. The new isolate's local clock is only20ms.
        assert!(promote_auth_edge_hit(
            &mut cache,
            scope.clone(),
            &hit,
            20.0,
            14_500.0
        ));
        assert!(cache.entries.front().unwrap().checked_at_ms < 0.0);
        assert_eq!(cache.get(&scope, 20.0), Some(enabled()));
        assert_eq!(cache.get(&scope, 519.0), Some(enabled()));
        assert_eq!(cache.get(&scope, 520.0), None);
        assert!(!promote_auth_edge_hit(
            &mut cache,
            scope.clone(),
            &hit,
            600.0,
            15_000.0
        ));
        assert!(cache.entries.is_empty());
    }

    #[test]
    fn edge_encoding_is_bounded_positive_only_and_origin_scoped() {
        let origin = "https://auth.example";
        let digest = api_key_digest("private fixture key");
        let scope = auth_check_cache_key("namespace_a", &digest).unwrap();
        let key = auth_edge_cache_key(origin, &scope).unwrap();
        assert_eq!(
            key,
            format!("{origin}/__blockzilla-auth-positive/v1/{scope}")
        );
        assert_ne!(
            auth_edge_cache_key("https://other.example", &scope).unwrap(),
            key
        );
        assert!(!key.contains("private fixture key"));
        assert!(auth_edge_cache_key("https://auth.example/path", &scope).is_none());
        let mut record = enabled();
        record.key_id = "k".repeat(64);
        record.customer_id = "c".repeat(64);
        record.label = "\\".repeat(128);
        let (bytes, _) =
            encode_auth_edge_envelope(origin, &scope, &digest, &record, 10_000.0, 10_000.0)
                .unwrap();
        assert!(bytes.len() <= AUTH_EDGE_MAX_BODY_BYTES);
        record.status = RpcApiKeyStatus::Disabled;
        assert!(
            encode_auth_edge_envelope(origin, &scope, &digest, &record, 10_000.0, 10_000.0)
                .is_none()
        );
        for (checked, now) in [
            (f64::NAN, 10_000.0),
            (10_000.0, 9_999.0),
            (10_000.0, 15_000.0),
        ] {
            assert!(
                encode_auth_edge_envelope(origin, &scope, &digest, &enabled(), checked, now)
                    .is_none()
            );
        }
    }
}

async fn read_rpc_body(req: &mut Request) -> std::result::Result<Vec<u8>, RpcBodyReadError> {
    let content_length = req
        .headers()
        .get("Content-Length")
        .map_err(|_| RpcBodyReadError::Read)?
        .and_then(|value| value.parse::<usize>().ok());
    if content_length.is_some_and(|length| length > RPC_REQUEST_BODY_MAX_BYTES) {
        return Err(RpcBodyReadError::TooLarge);
    }
    if content_length == Some(0) {
        return Ok(Vec::new());
    }
    let mut stream = req.stream().map_err(|_| RpcBodyReadError::Read)?;
    let mut body = Vec::with_capacity(content_length.unwrap_or(0));
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| RpcBodyReadError::Read)?;
        if body.len().saturating_add(chunk.len()) > RPC_REQUEST_BODY_MAX_BYTES {
            return Err(RpcBodyReadError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn finish_metered_rpc(
    execution: RpcExecution,
    api_key: &RpcApiKeyRecord,
    metrics: &AnalyticsEngineDataset,
    request_started: f64,
    profile: Option<&ProfileHandle>,
) -> Result<Response> {
    let metering = MeteredRequest::new(
        execution.method,
        execution.outcome,
        "uncached",
        "json_rpc",
        execution.request_bytes,
        execution.billable_backend_reads,
    )
    .with_storage(execution.storage);
    let mut response = finish_metered_response(
        execution.response,
        api_key,
        metrics,
        metering,
        request_started,
        profile,
    )?;
    response
        .headers_mut()
        .set("Cache-Control", "private, no-store")?;
    Ok(response)
}

struct MeteredRequest {
    method: &'static str,
    outcome: &'static str,
    cache_status: &'static str,
    transport: &'static str,
    request_bytes: usize,
    billable_backend_reads: u8,
    storage: StorageSnapshot,
}

impl MeteredRequest {
    fn new(
        method: &'static str,
        outcome: &'static str,
        cache_status: &'static str,
        transport: &'static str,
        request_bytes: usize,
        billable_backend_reads: u8,
    ) -> Self {
        Self {
            method,
            outcome,
            cache_status,
            transport,
            request_bytes,
            billable_backend_reads: billable_backend_reads.min(1),
            storage: StorageSnapshot::default(),
        }
    }

    fn with_storage(mut self, storage: StorageSnapshot) -> Self {
        self.storage = storage;
        self
    }
}

fn finish_metered_response(
    mut response: Response,
    api_key: &RpcApiKeyRecord,
    metrics: &AnalyticsEngineDataset,
    metering: MeteredRequest,
    request_started: f64,
    profile: Option<&ProfileHandle>,
) -> Result<Response> {
    let status = response.status_code();
    if metering.cache_status == "hit" {
        response
            .headers_mut()
            .set("X-Blockzilla-Origin-Expected-Bytes", "0")?;
        response
            .headers_mut()
            .set("X-Blockzilla-Storage-Bytes-Mode", "response-cache")?;
    }
    let latency_ms = (now_ms() - request_started).max(0.0);
    response.headers_mut().set(
        "X-Blockzilla-Cache",
        cache_receipt_value(metering.cache_status),
    )?;
    response.headers_mut().set(
        "X-Blockzilla-Billable-Reads",
        if metering.billable_backend_reads == 0 {
            "0"
        } else {
            "1"
        },
    )?;
    apply_storage_headers(&mut response, metering.storage)?;
    let point = AnalyticsEngineDataPointBuilder::new()
        .indexes([api_key.key_id.as_str()])
        .blobs([
            api_key.customer_id.as_str(),
            metering.method,
            metering.outcome,
            metering.cache_status,
            metering.transport,
        ])
        .doubles([
            1.0,
            f64::from(metering.billable_backend_reads),
            status as f64,
            latency_ms,
            metering.request_bytes as f64,
            metering.storage.r2_gets as f64,
            metering.storage.r2_heads as f64,
            metering.storage.r2_bytes as f64,
            metering.storage.s3_gets as f64,
            metering.storage.s3_heads as f64,
            metering.storage.s3_bytes as f64,
            metering.storage.archive_memory_hits as f64,
            metering.storage.archive_edge_hits as f64,
            metering.storage.r2_get_successes as f64,
            metering.storage.r2_head_successes as f64,
            metering.storage.s3_get_successes as f64,
            metering.storage.s3_head_successes as f64,
            metering.storage.foundation_r2_gets as f64,
            metering.storage.foundation_r2_bytes as f64,
            metering.storage.foundation_r2_get_successes as f64,
        ]);
    if point.write_to(metrics).is_err() {
        console_error!(
            "{}",
            json!({
                "event": "rpc_metrics_backend_error",
                "reason": "write_failed",
                "keyId": api_key.key_id.as_str(),
            })
        );
        let mut unavailable = json_error_profiled(
            503,
            "api_unavailable",
            "API metering is temporarily unavailable",
            profile,
        )?;
        unavailable.headers_mut().set(
            "X-Blockzilla-Cache",
            cache_receipt_value(metering.cache_status),
        )?;
        unavailable.headers_mut().set(
            "X-Blockzilla-Billable-Reads",
            if metering.billable_backend_reads == 0 {
                "0"
            } else {
                "1"
            },
        )?;
        apply_storage_headers(&mut unavailable, metering.storage)?;
        return Ok(unavailable);
    }
    Ok(response)
}

fn apply_storage_headers(response: &mut Response, storage: StorageSnapshot) -> Result<()> {
    for (name, value) in storage.headers() {
        response.headers_mut().set(name, &value.to_string())?;
    }
    response.headers_mut().set(
        "X-Blockzilla-Reader",
        if storage.reader_http_requests > 0 {
            "native-r2"
        } else {
            "none"
        },
    )?;
    Ok(())
}

fn cache_receipt_value(cache_status: &str) -> &'static str {
    match cache_status {
        "hit" => "HIT",
        "miss" => "MISS",
        "uncached" => "UNCACHED",
        _ => "BYPASS",
    }
}

fn api_unauthorized_response() -> Result<Response> {
    let mut response = json_error(
        401,
        "unauthorized",
        "A valid Bearer API key is required for this request",
    )?;
    response
        .headers_mut()
        .set("WWW-Authenticate", "Bearer realm=\"Blockzilla API\"")?;
    Ok(response)
}

enum StreamedRpcBody {
    Buffered(Vec<u8>),
    Stream(mpsc::Receiver<std::result::Result<Vec<u8>, worker::Error>>),
}

async fn handle_one_streamed(
    source: &WorkerSource,
    value: &Value,
) -> std::result::Result<Option<StreamedRpcBody>, Value> {
    let Ok(request) = serde_json::from_value::<RpcRequest>(value.clone()) else {
        return Ok(None);
    };
    let id = request.id.clone().unwrap_or(Value::Null);
    if request.jsonrpc.as_deref() != Some("2.0") {
        return Ok(None);
    }
    if request.params.as_ref().is_some_and(contains_json_parsed) {
        return Ok(None);
    }
    let Some(method) = request.method.as_deref() else {
        return Ok(None);
    };

    match method {
        "getBlock" => {
            let Ok((slot, config)) = get_block_params(&request) else {
                return Ok(None);
            };
            if !should_stream_get_block(config) {
                return Ok(None);
            }

            let block = match fetch_block(source, slot, access_fetch_mode(config)).await {
                Ok(Some(block)) => block,
                Ok(None) => {
                    let err = RpcError::skipped_slot(slot);
                    return Err(error_response(id, err.code, err.message));
                }
                Err(err) => {
                    let err = RpcError::internal(format!("failed to decode slot {slot}: {err}"));
                    return Err(error_response(id, err.code, err.message));
                }
            };
            let body = stream_json_rpc_get_block_success_body(source.clone(), id, block, config);
            Ok(Some(StreamedRpcBody::Stream(body)))
        }
        "getBlockTime" => {
            let params = match params_array(&request) {
                Ok(params) => params,
                Err(_) => return Ok(None),
            };
            let Some(slot) = params.first().and_then(Value::as_u64) else {
                return Ok(None);
            };
            let block = match fetch_block(source, slot, AccessFetchMode::None).await {
                Ok(Some(block)) => block,
                Ok(None) => {
                    let err = RpcError::skipped_slot(slot);
                    return Err(error_response(id, err.code, err.message));
                }
                Err(err) => {
                    let err = RpcError::internal(format!("failed to decode slot {slot}: {err}"));
                    return Err(error_response(id, err.code, err.message));
                }
            };
            let result = stream_block_time_value(source, block.block.header.block_time);
            stream_json_rpc_success(&id, result)
                .map(|bytes| Some(StreamedRpcBody::Buffered(bytes)))
                .map_err(|err| {
                    let err = RpcError::internal(format!(
                        "failed to encode response for slot {slot}: {err}"
                    ));
                    error_response(id, err.code, err.message)
                })
        }
        "getVersion" => {
            let started = now_ms();
            let mut result = Vec::with_capacity(64);
            result.extend_from_slice(br#"{"solana-core":"blockzilla-get-block/"#);
            result.extend_from_slice(env!("CARGO_PKG_VERSION").as_bytes());
            result.extend_from_slice(br#""}"#);
            source.record_elapsed(
                "render_streamed_version",
                started,
                result.len() as u64,
                "version",
                None,
            );
            stream_json_rpc_success(&id, result)
                .map(|bytes| Some(StreamedRpcBody::Buffered(bytes)))
                .map_err(|err| {
                    let err = RpcError::internal(format!("failed to encode response: {err}"));
                    error_response(id, err.code, err.message)
                })
        }
        _ => Ok(None),
    }
}

async fn handle_one(source: &WorkerSource, value: Value) -> Value {
    let request: RpcRequest = match serde_json::from_value(value) {
        Ok(request) => request,
        Err(err) => return error_response(Value::Null, -32600, err.to_string()),
    };
    let id = request.id.clone().unwrap_or(Value::Null);

    if request.jsonrpc.as_deref() != Some("2.0") {
        return error_response(id, -32600, "Invalid Request: jsonrpc must be \"2.0\"");
    }
    let Some(method) = request.method.as_deref() else {
        return error_response(id, -32600, "Invalid Request: missing method");
    };

    if request.params.as_ref().is_some_and(contains_json_parsed) {
        return error_response(
            id,
            -32602,
            "The jsonParsed encoding is not supported by this archive RPC",
        );
    }

    let result = match method {
        "getTransaction" => transaction::handle(source, &request).await,
        "getBlock" => handle_get_block(source, &request).await,
        "getBlockTime" => handle_get_block_time(source, &request).await,
        "getVersion" => Ok(json!({
            "solana-core": concat!("blockzilla-get-block/", env!("CARGO_PKG_VERSION"))
        })),
        _ => Err(RpcError::method_not_found(method)),
    };

    match result {
        Ok(result) => success_response(id, result),
        Err(err) => error_response(id, err.code, err.message),
    }
}

fn should_stream_get_block(config: GetBlockConfig) -> bool {
    match config.transaction_details {
        TransactionDetails::Full
        | TransactionDetails::None
        | TransactionDetails::Signatures
        | TransactionDetails::Accounts => true,
    }
}

async fn handle_get_block(
    source: &WorkerSource,
    request: &RpcRequest,
) -> std::result::Result<Value, RpcError> {
    let (slot, config) = get_block_params(request)?;
    let Some(block) = fetch_block(source, slot, access_fetch_mode(config))
        .await
        .map_err(|err| RpcError::internal(format!("failed to decode slot {slot}: {err}")))?
    else {
        return Err(RpcError::skipped_slot(slot));
    };
    render_block_value(source, &block, config, None)
        .await
        .map_err(|err| RpcError::internal(format!("failed to decode slot {slot}: {err}")))
}

async fn handle_get_block_time(
    source: &WorkerSource,
    request: &RpcRequest,
) -> std::result::Result<Value, RpcError> {
    let params = params_array(request)?;
    let slot = params
        .first()
        .and_then(Value::as_u64)
        .ok_or_else(|| RpcError::invalid_params("getBlockTime requires slot as first parameter"))?;
    let Some(block) = fetch_block(source, slot, AccessFetchMode::None)
        .await
        .map_err(|err| RpcError::internal(format!("failed to decode slot {slot}: {err}")))?
    else {
        return Err(RpcError::skipped_slot(slot));
    };
    Ok(rpc_block_time(block.block.header.block_time)
        .map(Value::from)
        .unwrap_or(Value::Null))
}

fn get_block_params(request: &RpcRequest) -> std::result::Result<(u64, GetBlockConfig), RpcError> {
    let params = params_array(request)?;
    let slot = params
        .first()
        .and_then(Value::as_u64)
        .ok_or_else(|| RpcError::invalid_params("getBlock requires slot as first parameter"))?;
    let config = parse_get_block_config(params.get(1)).map_err(RpcError::invalid_params)?;
    Ok((slot, config))
}

fn params_array(request: &RpcRequest) -> std::result::Result<Vec<Value>, RpcError> {
    match request.params.as_ref() {
        None => Ok(Vec::new()),
        Some(Value::Array(items)) => Ok(items.clone()),
        Some(_) => Err(RpcError::invalid_params("params must be an array")),
    }
}

fn success_response(id: Value, result: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "result": result,
        "id": id,
    })
}

fn error_response(id: Value, code: i64, message: impl Into<String>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "error": {
            "code": code,
            "message": message.into(),
        },
        "id": id,
    })
}

fn json_rpc_response_profiled(value: Value, profile: Option<&ProfileHandle>) -> Result<Response> {
    cached_json_response_profiled(&value, ERROR_CACHE_CONTROL, profile)
}

fn json_bytes_response_profiled(
    bytes: Vec<u8>,
    cache_control: &str,
    profile: Option<&ProfileHandle>,
) -> Result<Response> {
    let headers = Headers::new();
    headers.set("Cache-Control", cache_control)?;
    headers.set("Content-Type", "application/json")?;
    add_profile_headers(&headers, profile)?;
    Ok(Response::from_bytes(bytes)?.with_headers(headers))
}

fn json_stream_response_profiled(
    body: mpsc::Receiver<std::result::Result<Vec<u8>, worker::Error>>,
    cache_control: &str,
    profile: Option<&ProfileHandle>,
) -> Result<Response> {
    let headers = Headers::new();
    headers.set("Cache-Control", cache_control)?;
    headers.set("Content-Type", "application/json")?;
    add_profile_headers(&headers, profile)?;
    Ok(Response::from_stream(body)?.with_headers(headers))
}

#[derive(Debug, Clone, Copy)]
enum TransactionDetails {
    Full,
    Signatures,
    None,
    Accounts,
}

#[derive(Debug, Clone, Copy)]
struct GetBlockConfig {
    transaction_details: TransactionDetails,
    rewards: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AccessFetchMode {
    None,
    BlockhashOnly,
    Signatures,
    Full,
}

fn access_fetch_mode(config: GetBlockConfig) -> AccessFetchMode {
    if config.rewards {
        return AccessFetchMode::Full;
    }
    match config.transaction_details {
        TransactionDetails::None => AccessFetchMode::BlockhashOnly,
        TransactionDetails::Signatures => AccessFetchMode::Signatures,
        TransactionDetails::Full | TransactionDetails::Accounts => AccessFetchMode::Full,
    }
}

fn parse_get_block_config(value: Option<&Value>) -> std::result::Result<GetBlockConfig, String> {
    let mut config = GetBlockConfig {
        transaction_details: TransactionDetails::Full,
        rewards: true,
    };

    match value {
        None => {}
        Some(Value::String(encoding)) if encoding == "json" => {}
        Some(Value::String(encoding)) if encoding == "jsonParsed" => {
            return Err("The jsonParsed encoding is not supported by this archive RPC".to_string());
        }
        Some(Value::String(encoding)) => {
            return Err(format!("unsupported transaction encoding {encoding}"));
        }
        Some(Value::Object(map)) => {
            if let Some(encoding) = map.get("encoding").and_then(Value::as_str) {
                match encoding {
                    "json" => {}
                    "jsonParsed" => {
                        return Err(
                            "The jsonParsed encoding is not supported by this archive RPC"
                                .to_string(),
                        );
                    }
                    _ => return Err(format!("unsupported transaction encoding {encoding}")),
                }
            }
            if let Some(details) = map.get("transactionDetails").and_then(Value::as_str) {
                config.transaction_details = match details {
                    "full" => TransactionDetails::Full,
                    "signatures" => TransactionDetails::Signatures,
                    "none" => TransactionDetails::None,
                    "accounts" => TransactionDetails::Accounts,
                    _ => return Err(format!("unsupported transactionDetails {details}")),
                };
            }
            if let Some(rewards) = map.get("rewards") {
                config.rewards = rewards
                    .as_bool()
                    .ok_or_else(|| "rewards must be a boolean".to_string())?;
            }
        }
        Some(_) => return Err("getBlock config must be a string or object".to_string()),
    }

    Ok(config)
}

fn contains_json_parsed(value: &Value) -> bool {
    match value {
        Value::String(value) => value == "jsonParsed",
        Value::Array(items) => items.iter().any(contains_json_parsed),
        Value::Object(map) => map.values().any(contains_json_parsed),
        _ => false,
    }
}

async fn handle_probe_first(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    handle_probe(req, ctx, None).await
}

async fn handle_probe_slot(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let Some(slot) = ctx.param("slot") else {
        return json_error(400, "invalid_slot", "missing slot");
    };
    let slot = match slot.parse::<u64>() {
        Ok(slot) => slot,
        Err(_) => return json_error(400, "invalid_slot", "slot must be an unsigned integer"),
    };
    handle_probe(req, ctx, Some(slot)).await
}

async fn handle_probe(req: Request, ctx: RouteContext<()>, slot: Option<u64>) -> Result<Response> {
    let profile = request_profile(&req);
    let probe_started = now_ms();
    let source = match WorkerSource::from_env(&ctx.env, profile.clone()) {
        Ok(source) => source,
        Err(err) => return json_error_profiled(500, "config_error", &err, profile.as_ref()),
    };
    let epoch = query_epoch(&req).unwrap_or(10);
    let selected_slot = slot.unwrap_or(epoch * SLOTS_PER_EPOCH);
    match fetch_block(&source, selected_slot, AccessFetchMode::None).await {
        Ok(Some(block)) => {
            source.record_elapsed("probe_total", probe_started, 0, "ok", None);
            cached_json_response_profiled(
                &json!({
                    "source": {
                        "epoch": block.epoch,
                        "prefix": source.archive_prefix,
                    },
                    "indexRow": {
                        "slotOffset": block.block.header.slot % SLOTS_PER_EPOCH,
                        "blockOffset": block.index_row.block_offset,
                        "blockLen": block.index_row.block_len,
                        "accessOffset": block.index_row.access_offset,
                        "accessLen": block.index_row.access_len,
                    },
                    "block": {
                        "slot": block.block.header.slot,
                        "parentSlot": block.block.header.parent_slot,
                        "blockTime": block.block.header.block_time,
                        "blockHeight": block.block.header.block_height,
                        "txCount": block.block.tx_count,
                        "decodedTxRows": block.block.tx_rows.len(),
                        "messageBytes": block.block.message_bytes.len(),
                        "metadataBytes": block.block.metadata_bytes.len(),
                    }
                }),
                ERROR_CACHE_CONTROL,
                profile.as_ref(),
            )
        }
        Ok(None) => {
            source.record_elapsed("probe_total", probe_started, 0, "missing", None);
            json_error_profiled(
                404,
                "missing_slot",
                "slot not found in Blockzilla archive",
                profile.as_ref(),
            )
        }
        Err(err) => {
            console_error!("probe failed: {}", err);
            source.record_elapsed("probe_total", probe_started, 0, "error", None);
            json_error_profiled(502, "probe_error", &err, profile.as_ref())
        }
    }
}

fn query_epoch(req: &Request) -> Option<u64> {
    let url = req.url().ok()?;
    url.query_pairs()
        .find(|(key, _)| key == "epoch")
        .and_then(|(_, value)| value.parse().ok())
}

async fn render_route_block_bytes(
    source: &WorkerSource,
    request: BlockRequest,
    mode: RouteBlockMode,
    locator: Option<&str>,
) -> std::result::Result<Option<Vec<u8>>, String> {
    let Some(block) = fetch_direct_json_block(source, request.slot, locator).await? else {
        return Ok(None);
    };
    let config = GetBlockConfig {
        transaction_details: TransactionDetails::Full,
        rewards: request.include_rewards,
    };
    let bytes = match mode {
        RouteBlockMode::Full => {
            let mut writer = JsonByteWriter::with_capacity(block.decoded_len.saturating_mul(3));
            block_base64::stream_full_value_into(source, &block, config, &mut writer).await?;
            writer.into_inner()
        }
        RouteBlockMode::Lite => stream_get_block_lite_value(source, &block, config).await?,
    };
    stream_json_rpc_success(&Value::from(1), bytes).map(Some)
}

async fn render_route_block_response(
    source: &WorkerSource,
    request: BlockRequest,
    mode: RouteBlockMode,
    locator: Option<&str>,
) -> std::result::Result<Option<Response>, String> {
    if mode == RouteBlockMode::Lite {
        return render_route_block_bytes(source, request, mode, locator)
            .await?
            .map(|bytes| {
                json_bytes_response_profiled(bytes, BLOCK_CACHE_CONTROL, source.profile.as_ref())
                    .map_err(|e| e.to_string())
            })
            .transpose();
    }
    let Some(block) = fetch_direct_json_block(source, request.slot, locator).await? else {
        return Ok(None);
    };
    let config = GetBlockConfig {
        transaction_details: TransactionDetails::Full,
        rewards: request.include_rewards,
    };
    let body = stream_json_rpc_get_block_success_body_with_policy(
        source.clone(),
        Value::from(1),
        block,
        config,
        true,
        true,
    );
    let mut response =
        json_stream_response_profiled(body, BLOCK_CACHE_CONTROL, source.profile.as_ref())
            .map_err(|e| e.to_string())?;
    response
        .headers_mut()
        .set("X-Blockzilla-Body", "json-stream")
        .map_err(|e| e.to_string())?;
    Ok(Some(response))
}

async fn fetch_direct_json_block(
    source: &WorkerSource,
    slot: u64,
    locator: Option<&str>,
) -> std::result::Result<Option<FetchedHotBlock>, String> {
    let prepared = source.foundation_prepared.borrow_mut().take();
    if let Some(prepared) = prepared {
        let block = match prepared {
            foundation_first::Outcome::Complete {
                response,
                locator,
                length,
                digest,
            } => {
                let bytes =
                    foundation_first::read_complete_verified(response, length, digest).await?;
                bundle_object::decode_complete_bundle(source, slot, &bytes, &locator)?
            }
            foundation_first::Outcome::Resolution { checked, .. } => {
                resolution::fetch_checked_block(source, slot, checked).await?
            }
            foundation_first::Outcome::NotCached {
                source: Some(route),
            } => resolution::fetch_foundation_block(source, slot, route).await?,
            _ => return Err("Foundation result was not prepared for rendering".into()),
        };
        return Ok(Some(block));
    }
    if bundle_object::covered(source, slot) {
        if locator.is_some() {
            return Err("Stored slot bundles do not accept a client locator".into());
        }
        return bundle_object::fetch_block(source, slot).await;
    }
    if let Some(token) = locator {
        resolution::fetch_block_with_hint(source, slot, token).await
    } else {
        fetch_block(source, slot, AccessFetchMode::Full).await
    }
}

async fn foundation_binary_response(
    source: &WorkerSource,
    slot: u64,
    prepared: foundation_first::Outcome,
    ctx: &Rc<worker::Context>,
    metrics: &AnalyticsEngineDataset,
    key: &RpcApiKeyRecord,
) -> std::result::Result<Response, String> {
    match prepared {
        foundation_first::Outcome::NotCached {
            source: Some(route),
        } => {
            resolution::foundation_archive_binary_response(source, slot, route, ctx, metrics, key)
                .await
        }
        foundation_first::Outcome::Resolution { checked, .. } => {
            resolution::binary_response_checked(source, slot, checked, ctx, metrics, key).await
        }
        foundation_first::Outcome::Complete {
            response,
            length,
            digest,
            ..
        } => {
            let (_, body) = response.into_parts();
            let parts = stream_parts::response_and_completion_from_parts(
                Vec::new(),
                body,
                length as u64,
                Vec::new(),
                worker::ResponseBody::Empty,
                0,
                Vec::new(),
            )
            .map_err(|e| e.to_string())?;
            let mut response = parts.response;
            response
                .headers_mut()
                .set("Content-Type", foundation_first::BUNDLE_TYPE)
                .map_err(|e| e.to_string())?;
            response
                .headers_mut()
                .set("Cache-Control", BLOCK_CACHE_CONTROL)
                .map_err(|e| e.to_string())?;
            response
                .headers_mut()
                .set("ETag", &format!("\"{}\"", hex_lower(&digest)))
                .map_err(|e| e.to_string())?;
            response
                .headers_mut()
                .set("X-Blockzilla-Body", "native-stream")
                .map_err(|e| e.to_string())?;
            response
                .headers_mut()
                .set("X-Blockzilla-Storage-Bytes-Mode", "streamed-completion")
                .map_err(|e| e.to_string())?;
            response
                .headers_mut()
                .set("X-Blockzilla-Origin-Expected-Bytes", "0")
                .map_err(|e| e.to_string())?;
            response
                .headers_mut()
                .set(
                    "X-Blockzilla-Foundation-Expected-Bytes",
                    &length.to_string(),
                )
                .map_err(|e| e.to_string())?;
            add_profile_headers(response.headers(), source.profile.as_ref())
                .map_err(|e| e.to_string())?;
            let dataset = metrics.clone();
            let key_id = key.key_id.clone();
            let customer_id = key.customer_id.clone();
            ctx.wait_until(async move {
                let Ok(value) = wasm_bindgen_futures::JsFuture::from(parts.completion).await else {
                    console_error!("Foundation complete body failed or was cancelled");
                    return;
                };
                let bytes = js_sys::Reflect::get(&value, &JsValue::from_str("hotBytes"))
                    .ok()
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0);
                let mut doubles = [0.0; 20];
                doubles[7] = bytes;
                let _ = AnalyticsEngineDataPointBuilder::new()
                    .indexes([key_id.as_str()])
                    .blobs([
                        customer_id.as_str(),
                        "getBlock",
                        "foundation_body_complete",
                        "continuation",
                        "http_binary",
                    ])
                    .doubles(doubles)
                    .write_to(&dataset);
            });
            Ok(response)
        }
        _ => Err("Foundation result was not prepared for binary rendering".into()),
    }
}

struct FetchedHotBlock {
    epoch: u64,
    index_row: ArchiveV2GetBlockIndexRow,
    row: ArchiveV2HotBlockIndexRow,
    decoded_len: usize,
    block: ArchiveV2HotBlockBlob,
    access: Option<FetchedAccess>,
    message_schema: MessageSchema,
    metadata_schema: MetadataSchema,
}

struct FetchedAccessLite {
    blockhash: [u8; 32],
    previous_blockhash: [u8; 32],
    signature_counts: Vec<u8>,
    signatures: Vec<u8>,
}

#[derive(Debug, Deserialize, SchemaRead)]
struct LegacyBlockAccessBlobV1 {
    version: u16,
    flags: u32,
    blockhash: [u8; 32],
    previous_blockhash: [u8; 32],
    signature_counts: Vec<u8>,
    signatures: Vec<u8>,
    pubkeys: Vec<ArchiveV2BlockAccessPubkey>,
    blockhashes: Vec<ArchiveV2BlockAccessBlockhash>,
}

impl From<LegacyBlockAccessBlobV1> for ArchiveV2BlockAccessBlob {
    fn from(value: LegacyBlockAccessBlobV1) -> Self {
        Self {
            version: value.version,
            flags: value.flags,
            blockhash: value.blockhash,
            previous_blockhash: value.previous_blockhash,
            signature_counts: value.signature_counts,
            signatures: value.signatures,
            pubkeys: value.pubkeys,
            blockhashes: value.blockhashes,
            vote_hashes: Vec::new(),
        }
    }
}

#[derive(Debug, Deserialize, SchemaRead)]
struct LegacyCompactMetaV1 {
    err: Option<Vec<u8>>,
    fee: u64,
    pre_balances: Vec<u64>,
    post_balances: Vec<u64>,
    inner_instructions: Option<Vec<CompactInnerInstructions>>,
    logs: Option<CompactLogStream>,
    pre_token_balances: Vec<CompactTokenBalance>,
    post_token_balances: Vec<CompactTokenBalance>,
    rewards: Vec<CompactReward>,
    loaded_writable_addresses: Vec<CompactPubkey>,
    loaded_readonly_addresses: Vec<CompactPubkey>,
    return_data: Option<CompactReturnData>,
    compute_units_consumed: Option<u64>,
    cost_units: Option<u64>,
}

impl TryFrom<LegacyCompactMetaV1> for CompactMetaV1 {
    type Error = String;

    fn try_from(value: LegacyCompactMetaV1) -> std::result::Result<Self, Self::Error> {
        let err = value
            .err
            .as_deref()
            .map(StoredTransactionError::from_stored_wincode_bytes)
            .transpose()
            .map_err(|err| err.to_string())?;
        Ok(Self {
            err,
            fee: value.fee,
            pre_balances: value.pre_balances,
            post_balances: value.post_balances,
            inner_instructions: value.inner_instructions,
            logs: value.logs,
            pre_token_balances: value.pre_token_balances,
            post_token_balances: value.post_token_balances,
            rewards: value.rewards,
            loaded_writable_addresses: value.loaded_writable_addresses,
            loaded_readonly_addresses: value.loaded_readonly_addresses,
            return_data: value.return_data,
            compute_units_consumed: value.compute_units_consumed,
            cost_units: value.cost_units,
        })
    }
}

enum FetchedAccess {
    Full(ArchiveV2BlockAccessBlob),
    Lite(FetchedAccessLite),
}

impl FetchedAccess {
    fn full(&self) -> Option<&ArchiveV2BlockAccessBlob> {
        match self {
            Self::Full(access) => Some(access),
            Self::Lite(_) => None,
        }
    }

    fn blockhash(&self) -> &[u8; 32] {
        match self {
            Self::Full(access) => &access.blockhash,
            Self::Lite(access) => &access.blockhash,
        }
    }

    fn previous_blockhash(&self) -> &[u8; 32] {
        match self {
            Self::Full(access) => &access.previous_blockhash,
            Self::Lite(access) => &access.previous_blockhash,
        }
    }

    fn signatures(&self) -> &[u8] {
        match self {
            Self::Full(access) => &access.signatures,
            Self::Lite(access) => &access.signatures,
        }
    }
}

async fn fetch_block(
    source: &WorkerSource,
    slot: u64,
    access_mode: AccessFetchMode,
) -> std::result::Result<Option<FetchedHotBlock>, String> {
    if bundle_object::covered(source, slot) {
        return bundle_object::fetch_block(source, slot).await;
    }
    if resolution::covered(source, slot) {
        return resolution::fetch_block(source, slot).await;
    }
    if source.stored_compact {
        return stored::fetch_block(source, slot, access_mode).await;
    }
    let total_started = now_ms();
    let epoch = epoch_for_slot(slot);
    let Some(index_row) = read_get_block_index_row(source, epoch, slot).await? else {
        source.record_elapsed("fetch_block_total", total_started, 0, "missing", None);
        return Ok(None);
    };
    fetch_block_from_get_block_index(source, total_started, epoch, slot, index_row, access_mode)
        .await
}

async fn fetch_block_bundle_bytes(
    source: &WorkerSource,
    slot: u64,
    access_mode: BlockBinAccessMode,
) -> std::result::Result<Option<Vec<u8>>, String> {
    if source.stored_compact {
        return stored::fetch_bundle(source, slot, access_mode).await;
    }
    let total_started = now_ms();
    let epoch = epoch_for_slot(slot);
    let Some(index_row) = read_get_block_index_row_with_access(
        source,
        epoch,
        slot,
        access_mode == BlockBinAccessMode::Include,
    )
    .await?
    else {
        source.record_elapsed("fetch_block_bin_total", total_started, 0, "missing", None);
        return Ok(None);
    };
    let blocks_path = epoch_file(&source.archive_prefix, epoch, ARCHIVE_V2_BLOCKS_FILE);
    let block_fetch = fetch_compressed_block(source, &blocks_path, &index_row);
    let access_fetch = async {
        if access_mode == BlockBinAccessMode::Include {
            let access_path =
                epoch_file(&source.archive_prefix, epoch, ARCHIVE_V2_BLOCK_ACCESS_FILE);
            let started = now_ms();
            let bytes = source
                .get_cached_range(
                    &access_path,
                    index_row.access_offset,
                    index_row.access_len as usize,
                )
                .await?;
            source.record_elapsed(
                "access_fetch",
                started,
                bytes.len() as u64,
                "block_access_bundle",
                None,
            );
            Ok(Some(bytes))
        } else {
            Ok::<_, String>(None)
        }
    };
    let (hot_block, block_access) = future::try_join(block_fetch, access_fetch).await?;
    let started = now_ms();
    let bundle = BlockzillaGetBlockBundleV1 {
        version: WINCODE_BLOCKZILLA_GET_BLOCK_BUNDLE_VERSION,
        slot,
        hot_block_encoding: BlockzillaGetBlockBlobEncoding::ZstdWincode,
        hot_block,
        block_access_encoding: BlockzillaGetBlockBlobEncoding::Wincode,
        block_access,
    };
    let bytes = wincode::config::serialize(&bundle, wincode_leb128_config())
        .map_err(|err| format!("encode blockzilla getBlock bundle for slot {slot}: {err}"))?;
    source.record_elapsed(
        "bundle_encode",
        started,
        bytes.len() as u64,
        access_mode.cache_key_suffix(),
        None,
    );
    source.record_elapsed(
        "fetch_block_bin_total",
        total_started,
        bytes.len() as u64,
        access_mode.cache_key_suffix(),
        None,
    );
    Ok(Some(bytes))
}

async fn read_get_block_index_row(
    source: &WorkerSource,
    epoch: u64,
    slot: u64,
) -> std::result::Result<Option<ArchiveV2GetBlockIndexRow>, String> {
    read_get_block_index_row_with_access(source, epoch, slot, true).await
}

async fn read_get_block_index_row_with_access(
    source: &WorkerSource,
    epoch: u64,
    slot: u64,
    require_access: bool,
) -> std::result::Result<Option<ArchiveV2GetBlockIndexRow>, String> {
    let index_path = epoch_file(
        &source.archive_prefix,
        epoch,
        ARCHIVE_V2_GET_BLOCK_INDEX_FILE,
    );
    let slot_index = slot % SLOTS_PER_EPOCH;
    let offset = slot_index
        .checked_mul(ARCHIVE_V2_GET_BLOCK_INDEX_ROW_LEN as u64)
        .ok_or_else(|| "get-block index row offset overflow".to_string())?;
    let started = now_ms();
    let bytes = source
        .get_cached_range(&index_path, offset, ARCHIVE_V2_GET_BLOCK_INDEX_ROW_LEN)
        .await?;
    let row = ArchiveV2GetBlockIndexRow {
        block_offset: u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
        block_len: u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
        access_offset: u64::from_le_bytes(bytes[12..20].try_into().unwrap()),
        access_len: u32::from_le_bytes(bytes[20..24].try_into().unwrap()),
    };
    if row.block_len == 0 || (require_access && row.access_len == 0) {
        source.record_elapsed("get_block_index", started, 0, "missing_slot", None);
        Ok(None)
    } else {
        source.record_elapsed("get_block_index", started, 0, "found", None);
        Ok(Some(row))
    }
}

async fn fetch_block_from_get_block_index(
    source: &WorkerSource,
    total_started: f64,
    epoch: u64,
    slot: u64,
    index_row: ArchiveV2GetBlockIndexRow,
    access_mode: AccessFetchMode,
) -> std::result::Result<Option<FetchedHotBlock>, String> {
    let blocks_path = epoch_file(&source.archive_prefix, epoch, ARCHIVE_V2_BLOCKS_FILE);
    let access_path = (access_mode != AccessFetchMode::None)
        .then(|| epoch_file(&source.archive_prefix, epoch, ARCHIVE_V2_BLOCK_ACCESS_FILE));
    let block_fetch = async { fetch_compressed_block(source, &blocks_path, &index_row).await };
    let access_fetch = async {
        let Some(access_path) = access_path.as_ref() else {
            return Ok::<Option<Vec<u8>>, String>(None);
        };
        let started = now_ms();
        let bytes = source
            .get_cached_range(
                access_path,
                index_row.access_offset,
                index_row.access_len as usize,
            )
            .await?;
        source.record_elapsed(
            "access_fetch",
            started,
            bytes.len() as u64,
            "block_access",
            None,
        );
        Ok(Some(bytes))
    };
    let (compressed, access_bytes) = future::try_join(block_fetch, access_fetch).await?;

    let block_bytes = decode_zstd_block_bytes(source, slot, &compressed)?;
    let started = now_ms();
    let block: ArchiveV2HotBlockBlob = deserialize_archive_v2_hot_block_blob(&block_bytes)
        .map_err(|err| format!("decode Blockzilla hot block for slot {slot}: {err}"))?;
    source.record_elapsed(
        "wincode_decode",
        started,
        block_bytes.len() as u64,
        "hot_block",
        None,
    );
    if block.header.slot != slot {
        return Err(format!(
            "decoded slot {} but request was {}",
            block.header.slot, slot
        ));
    }
    let tx_count = u32::try_from(block.tx_rows.len())
        .map_err(|_| format!("slot {slot} transaction count exceeds u32::MAX"))?;
    let signature_count = block
        .tx_rows
        .iter()
        .try_fold(0u32, |acc, row| {
            acc.checked_add(u32::from(row.signature_count))
        })
        .ok_or_else(|| format!("slot {slot} signature count overflow"))?;
    let uncompressed_len = u32::try_from(block_bytes.len())
        .map_err(|_| format!("slot {slot} decoded block exceeds u32::MAX"))?;
    let row = ArchiveV2HotBlockIndexRow {
        block_id: u32::MAX,
        slot,
        compressed_offset: index_row.block_offset,
        compressed_len: index_row.block_len,
        uncompressed_len,
        tx_count,
        first_tx_ordinal: 0,
        first_signature_ordinal: 0,
        signature_count,
    };
    let access = if let Some(bytes) = access_bytes {
        decode_block_access_bytes(source, &row, &bytes, access_mode)?
    } else {
        None
    };
    source.record_elapsed(
        "fetch_block_total",
        total_started,
        block_bytes.len() as u64,
        "ok_direct",
        None,
    );
    Ok(Some(FetchedHotBlock {
        epoch,
        index_row,
        row,
        decoded_len: block_bytes.len(),
        block,
        access,
        message_schema: MessageSchema::Current,
        metadata_schema: MetadataSchema::Current,
    }))
}

async fn fetch_compressed_block(
    source: &WorkerSource,
    blocks_path: &str,
    index_row: &ArchiveV2GetBlockIndexRow,
) -> std::result::Result<Vec<u8>, String> {
    let started = now_ms();
    let compressed = source
        .get_cached_range(
            blocks_path,
            index_row.block_offset,
            index_row.block_len as usize,
        )
        .await?;
    source.record_elapsed(
        "block_fetch",
        started,
        compressed.len() as u64,
        "zstd_block",
        None,
    );
    Ok(compressed)
}

fn decode_zstd_block_bytes(
    source: &WorkerSource,
    slot: u64,
    compressed: &[u8],
) -> std::result::Result<Vec<u8>, String> {
    let started = now_ms();
    let mut decoder =
        StreamingDecoder::new_with_max_window_size(compressed, MAX_DECODED_BLOCK_BYTES as u64)
            .map_err(|err| format!("zstd-decode init slot {slot}: {err}"))?;
    let content_size = usize::try_from(decoder.decoder.content_size()).unwrap_or(0);
    if content_size > MAX_DECODED_BLOCK_BYTES {
        return Err(format!(
            "slot {slot} decoded block exceeds {MAX_DECODED_BLOCK_BYTES} bytes"
        ));
    }
    let mut block_bytes = Vec::with_capacity(content_size);
    decoder
        .by_ref()
        .take((MAX_DECODED_BLOCK_BYTES + 1) as u64)
        .read_to_end(&mut block_bytes)
        .map_err(|err| format!("zstd-decode read slot {slot}: {err}"))?;
    if block_bytes.len() > MAX_DECODED_BLOCK_BYTES {
        return Err(format!(
            "slot {slot} decoded block exceeds {MAX_DECODED_BLOCK_BYTES} bytes"
        ));
    }
    source.record_elapsed(
        "zstd_decode",
        started,
        block_bytes.len() as u64,
        "hot_block",
        None,
    );
    Ok(block_bytes)
}

fn decode_block_access_bytes(
    source: &WorkerSource,
    hot_row: &ArchiveV2HotBlockIndexRow,
    bytes: &[u8],
    mode: AccessFetchMode,
) -> std::result::Result<Option<FetchedAccess>, String> {
    let started = now_ms();
    let access = match mode {
        AccessFetchMode::Full => {
            let access = decode_full_access_blob(bytes, hot_row.slot)?;
            validate_access_blob(&access, hot_row)?;
            FetchedAccess::Full(access)
        }
        AccessFetchMode::BlockhashOnly | AccessFetchMode::Signatures => {
            let access = decode_lite_access_blob(
                bytes,
                matches!(mode, AccessFetchMode::Signatures),
                hot_row.slot,
            )?;
            if mode == AccessFetchMode::Signatures {
                validate_lite_access_blob(&access, hot_row)?;
            }
            FetchedAccess::Lite(access)
        }
        AccessFetchMode::None => return Ok(None),
    };
    source.record_elapsed(
        "access_decode",
        started,
        bytes.len() as u64,
        "block_access",
        None,
    );
    Ok(Some(access))
}

fn decode_full_access_blob(
    bytes: &[u8],
    slot: u64,
) -> std::result::Result<ArchiveV2BlockAccessBlob, String> {
    match wincode::config::deserialize::<ArchiveV2BlockAccessBlob, _>(
        bytes,
        wincode_leb128_config(),
    ) {
        Ok(access) => Ok(access),
        Err(primary_err) => {
            let legacy: LegacyBlockAccessBlobV1 =
                wincode::config::deserialize(bytes, wincode_leb128_config()).map_err(
                    |legacy_err| {
                        format!(
                            "decode Blockzilla block-access sidecar for slot {slot}: {primary_err}; legacy v1 decode: {legacy_err}"
                        )
                    },
                )?;
            if legacy.version != 1 {
                return Err(format!(
                    "slot {slot} block-access version {} is unsupported",
                    legacy.version
                ));
            }
            Ok(legacy.into())
        }
    }
}

fn decode_lite_access_blob(
    bytes: &[u8],
    include_signatures: bool,
    slot: u64,
) -> std::result::Result<FetchedAccessLite, String> {
    let mut reader = bytes;
    let version: u16 = read_wincode_value(&mut reader)
        .map_err(|err| format!("slot {slot} read block-access version: {err}"))?;
    if version != WINCODE_ARCHIVE_V2_BLOCK_ACCESS_VERSION && version != 1 {
        return Err(format!(
            "slot {slot} block-access version {version} is unsupported"
        ));
    }
    let _: u32 = read_wincode_value(&mut reader)
        .map_err(|err| format!("slot {slot} read block-access flags: {err}"))?;
    let blockhash = reader
        .take_array::<32>()
        .map_err(|err| format!("slot {slot} read block-access blockhash: {err}"))?;
    let previous_blockhash = reader
        .take_array::<32>()
        .map_err(|err| format!("slot {slot} read block-access previous blockhash: {err}"))?;
    if !include_signatures {
        return Ok(FetchedAccessLite {
            blockhash,
            previous_blockhash,
            signature_counts: Vec::new(),
            signatures: Vec::new(),
        });
    }
    let signature_counts: Vec<u8> = read_wincode_value(&mut reader)
        .map_err(|err| format!("slot {slot} read block-access signature counts: {err}"))?;
    let signatures: Vec<u8> = read_wincode_value(&mut reader)
        .map_err(|err| format!("slot {slot} read block-access signatures: {err}"))?;
    Ok(FetchedAccessLite {
        blockhash,
        previous_blockhash,
        signature_counts,
        signatures,
    })
}

fn validate_lite_access_blob(
    access: &FetchedAccessLite,
    hot_row: &ArchiveV2HotBlockIndexRow,
) -> std::result::Result<(), String> {
    if access.signature_counts.len() != hot_row.tx_count as usize {
        return Err(format!(
            "slot {} block-access has {} signature counts, expected {}",
            hot_row.slot,
            access.signature_counts.len(),
            hot_row.tx_count
        ));
    }
    let signature_count: usize = access
        .signature_counts
        .iter()
        .map(|count| usize::from(*count))
        .sum();
    if signature_count != hot_row.signature_count as usize {
        return Err(format!(
            "slot {} block-access has {} signatures by tx counts, expected {}",
            hot_row.slot, signature_count, hot_row.signature_count
        ));
    }
    let expected_bytes = signature_count
        .checked_mul(SIGNATURE_BYTES as usize)
        .ok_or_else(|| format!("slot {} signature byte count overflow", hot_row.slot))?;
    if access.signatures.len() != expected_bytes {
        return Err(format!(
            "slot {} block-access signature bytes {}, expected {}",
            hot_row.slot,
            access.signatures.len(),
            expected_bytes
        ));
    }
    Ok(())
}

fn validate_access_blob(
    access: &ArchiveV2BlockAccessBlob,
    hot_row: &ArchiveV2HotBlockIndexRow,
) -> std::result::Result<(), String> {
    if access.version != WINCODE_ARCHIVE_V2_BLOCK_ACCESS_VERSION && access.version != 1 {
        return Err(format!(
            "slot {} block-access version {} is unsupported",
            hot_row.slot, access.version
        ));
    }
    if access.signature_counts.len() != hot_row.tx_count as usize {
        return Err(format!(
            "slot {} block-access has {} signature counts, expected {}",
            hot_row.slot,
            access.signature_counts.len(),
            hot_row.tx_count
        ));
    }
    let signature_count: usize = access
        .signature_counts
        .iter()
        .map(|count| usize::from(*count))
        .sum();
    if signature_count != hot_row.signature_count as usize {
        return Err(format!(
            "slot {} block-access has {} signatures by tx counts, expected {}",
            hot_row.slot, signature_count, hot_row.signature_count
        ));
    }
    let expected_bytes = signature_count
        .checked_mul(SIGNATURE_BYTES as usize)
        .ok_or_else(|| "block-access signature length overflow".to_string())?;
    if access.signatures.len() != expected_bytes {
        return Err(format!(
            "slot {} block-access signature bytes {}, expected {}",
            hot_row.slot,
            access.signatures.len(),
            expected_bytes
        ));
    }
    Ok(())
}

async fn render_block_value(
    source: &WorkerSource,
    fetched: &FetchedHotBlock,
    config: GetBlockConfig,
    route_mode: Option<RouteBlockMode>,
) -> std::result::Result<Value, String> {
    let render_started = now_ms();
    let mut resolver = Resolver::new(
        source,
        fetched.access.as_ref().and_then(FetchedAccess::full),
    );
    let blockhash = match fetched.access.as_ref() {
        Some(access) => base58_32(access.blockhash()),
        None => {
            resolver
                .resolve_blockhash_id(fetched.block.header.blockhash_id as i32)
                .await?
        }
    };
    let previous_blockhash = match fetched.access.as_ref() {
        Some(access) => base58_32(access.previous_blockhash()),
        None => {
            resolver
                .resolve_blockhash_id(fetched.block.header.previous_blockhash_id as i32)
                .await?
        }
    };

    let mut out = Map::new();
    out.insert("blockhash".to_string(), Value::String(blockhash));
    out.insert(
        "previousBlockhash".to_string(),
        Value::String(previous_blockhash),
    );
    out.insert(
        "parentSlot".to_string(),
        Value::from(fetched.block.header.parent_slot),
    );
    out.insert(
        "blockTime".to_string(),
        rpc_block_time(fetched.block.header.block_time)
            .map(Value::from)
            .unwrap_or(Value::Null),
    );
    out.insert(
        "blockHeight".to_string(),
        fetched
            .block
            .header
            .block_height
            .map(Value::from)
            .unwrap_or(Value::Null),
    );
    if config.rewards {
        out.insert(
            "numRewardPartitions".into(),
            fetched
                .block
                .header
                .rewards
                .as_ref()
                .and_then(|rewards| rewards.num_partitions)
                .map(Value::from)
                .unwrap_or(Value::Null),
        );
        out.insert(
            "rewards".to_string(),
            rewards_value(&mut resolver, fetched.block.header.rewards.as_ref()).await?,
        );
    }

    match route_mode {
        Some(RouteBlockMode::Lite) => {
            out.insert(
                "transactions".to_string(),
                transactions_value(&mut resolver, fetched, true, false).await?,
            );
        }
        None | Some(RouteBlockMode::Full) => match config.transaction_details {
            TransactionDetails::Full => {
                out.insert(
                    "transactions".to_string(),
                    transactions_value(&mut resolver, fetched, false, true).await?,
                );
            }
            TransactionDetails::Accounts => {
                out.insert(
                    "transactions".to_string(),
                    account_transactions_value(&mut resolver, fetched, config.rewards).await?,
                );
            }
            TransactionDetails::Signatures => {
                out.insert(
                    "signatures".to_string(),
                    signatures_value(&resolver, fetched).await?,
                );
            }
            TransactionDetails::None => {}
        },
    }
    source.record_elapsed("render_total", render_started, 0, "json_value", None);
    Ok(Value::Object(out))
}

fn stream_json_rpc_success(id: &Value, result: Vec<u8>) -> std::result::Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(result.len().saturating_add(96));
    out.extend_from_slice(b"{\"jsonrpc\":\"2.0\",\"result\":");
    out.extend_from_slice(&result);
    out.extend_from_slice(b",\"id\":");
    serde_json::to_writer(&mut out, id).map_err(|err| format!("encode JSON-RPC id: {err}"))?;
    out.push(b'}');
    Ok(out)
}

fn stream_json_rpc_success_prefix(w: &mut JsonByteWriter) {
    w.raw(b"{\"jsonrpc\":\"2.0\",\"result\":");
}

fn stream_json_rpc_success_suffix(
    w: &mut JsonByteWriter,
    id: &Value,
) -> std::result::Result<(), String> {
    w.raw(b",\"id\":");
    w.json(id)
        .map_err(|err| format!("encode JSON-RPC id: {err}"))?;
    w.raw(b"}");
    Ok(())
}

fn stream_json_rpc_get_block_success_body(
    source: WorkerSource,
    id: Value,
    fetched: FetchedHotBlock,
    config: GetBlockConfig,
) -> mpsc::Receiver<std::result::Result<Vec<u8>, worker::Error>> {
    stream_json_rpc_get_block_success_body_with_policy(source, id, fetched, config, false, false)
}

fn stream_json_rpc_get_block_success_body_with_policy(
    source: WorkerSource,
    id: Value,
    fetched: FetchedHotBlock,
    config: GetBlockConfig,
    abort_render_errors: bool,
    base64_transactions: bool,
) -> mpsc::Receiver<std::result::Result<Vec<u8>, worker::Error>> {
    let (sender, receiver) = mpsc::channel(4);
    let mut error_sender = sender.clone();
    wasm_bindgen_futures::spawn_local(async move {
        let started = now_ms();
        let mut w = JsonByteWriter::channel(JSON_STREAM_CHUNK_BYTES, sender);
        let result = async {
            stream_json_rpc_success_prefix(&mut w);
            if base64_transactions {
                block_base64::stream_full_value_into(&source, &fetched, config, &mut w).await?;
            } else {
                stream_get_block_value_into(&source, &fetched, config, &mut w).await?;
            }
            stream_json_rpc_success_suffix(&mut w, &id)?;
            Ok::<(), String>(())
        }
        .await;
        let bytes = w.len() as u64;
        match result {
            Ok(()) => {
                if let Err(err) = w.flush_chunk_async().await {
                    console_error!("failed to finish getBlock response stream: {err}");
                }
                source.record_elapsed(
                    "render_streamed_get_block",
                    started,
                    bytes,
                    "stream_body",
                    None,
                );
            }
            Err(err) => {
                let message = format!("failed to stream getBlock response: {err}");
                console_error!("{message}");
                if !abort_render_errors && w.sent_bytes() == 0 {
                    let fallback = serde_json::to_vec(&error_response(id, -32000, message.clone()))
                        .map_err(|err| worker::Error::RustError(err.to_string()));
                    match fallback {
                        Ok(bytes) => {
                            let _ = error_sender.send(Ok(bytes)).await;
                        }
                        Err(err) => {
                            let _ = error_sender.send(Err(err)).await;
                        }
                    }
                } else {
                    let _ = error_sender
                        .send(Err(worker::Error::RustError(message)))
                        .await;
                }
                source.record_elapsed(
                    "render_streamed_get_block",
                    started,
                    bytes,
                    "stream_body_error",
                    None,
                );
            }
        }
    });
    receiver
}

async fn stream_resolved_pubkey_value(
    w: &mut JsonByteWriter,
    resolver: &mut Resolver<'_>,
    key: CompactPubkey,
) -> std::result::Result<(), String> {
    let bytes = resolver.resolve_pubkey_bytes(key).await?;
    w.base58_32(&bytes);
    Ok(())
}

async fn stream_resolved_recent_blockhash_value(
    w: &mut JsonByteWriter,
    resolver: &mut Resolver<'_>,
    value: &OwnedCompactRecentBlockhash,
) -> std::result::Result<(), String> {
    let bytes = resolver.resolve_recent_blockhash_bytes(value).await?;
    w.base58_32(&bytes);
    Ok(())
}

fn stream_block_time_value(source: &WorkerSource, block_time: Option<i64>) -> Vec<u8> {
    let started = now_ms();
    let mut w = JsonByteWriter::with_capacity(20);
    w.option_i64(rpc_block_time(block_time));
    let out = w.into_inner();
    source.record_elapsed(
        "render_streamed_block_time",
        started,
        out.len() as u64,
        "block_time",
        None,
    );
    out
}

async fn stream_get_block_value_into(
    source: &WorkerSource,
    fetched: &FetchedHotBlock,
    config: GetBlockConfig,
    w: &mut JsonByteWriter,
) -> std::result::Result<(), String> {
    match config.transaction_details {
        TransactionDetails::Full => {
            return stream_get_block_full_value_into(source, fetched, config, w).await;
        }
        TransactionDetails::Accounts => {
            return stream_get_block_accounts_value_into(source, fetched, config, w).await;
        }
        TransactionDetails::None | TransactionDetails::Signatures => {}
    }

    let started = now_ms();
    let start_len = w.len();
    let access = fetched
        .access
        .as_ref()
        .ok_or_else(|| "streamed getBlock path requires block access".to_string())?;
    w.raw(b"{\"blockhash\":");
    w.base58_32(access.blockhash());
    w.raw(b",\"previousBlockhash\":");
    w.base58_32(access.previous_blockhash());
    w.raw(b",\"parentSlot\":");
    w.u64(fetched.block.header.parent_slot);
    w.raw(b",\"blockTime\":");
    w.option_i64(rpc_block_time(fetched.block.header.block_time));
    w.raw(b",\"blockHeight\":");
    w.option_u64(fetched.block.header.block_height);
    if config.rewards {
        let mut resolver = Resolver::new(
            source,
            fetched.access.as_ref().and_then(FetchedAccess::full),
        );
        w.raw(b",\"rewards\":");
        stream_rewards_value(w, &mut resolver, fetched.block.header.rewards.as_ref()).await?;
        stream_reward_partitions(w, fetched.block.header.rewards.as_ref());
    }

    if matches!(config.transaction_details, TransactionDetails::Signatures) {
        w.raw(b",\"signatures\":[");
        let mut signature_index = 0usize;
        let mut first = true;
        for row in &fetched.block.tx_rows {
            if row.signature_count > 0 {
                let start = signature_index
                    .checked_mul(SIGNATURE_BYTES as usize)
                    .ok_or_else(|| "signature byte offset overflow".to_string())?;
                let end = start
                    .checked_add(SIGNATURE_BYTES as usize)
                    .ok_or_else(|| "signature byte end overflow".to_string())?;
                let signature = access.signatures().get(start..end).ok_or_else(|| {
                    "signature sidecar ended before first transaction signature".to_string()
                })?;
                if !first {
                    w.raw(b",");
                }
                first = false;
                w.base58_64(signature.try_into().expect("checked signature len"));
                if signature_index & 0x3ff == 0x3ff {
                    w.flush_chunk_async().await?;
                }
            }
            signature_index = signature_index
                .checked_add(usize::from(row.signature_count))
                .ok_or_else(|| "signature index overflow".to_string())?;
        }
        w.raw(b"]");
    }

    w.raw(b"}");
    let detail = match config.transaction_details {
        TransactionDetails::Signatures => "signatures",
        TransactionDetails::None => "none",
        TransactionDetails::Full | TransactionDetails::Accounts => unreachable!("handled above"),
    };
    source.record_elapsed(
        "render_streamed_get_block",
        started,
        w.len().saturating_sub(start_len) as u64,
        detail,
        None,
    );
    Ok(())
}

async fn stream_get_block_full_value(
    source: &WorkerSource,
    fetched: &FetchedHotBlock,
    config: GetBlockConfig,
) -> std::result::Result<Vec<u8>, String> {
    let full_access = fetched
        .access
        .as_ref()
        .and_then(FetchedAccess::full)
        .ok_or_else(|| "streamed full getBlock path requires full block access".to_string())?;
    let estimated = full_json_capacity_hint(fetched, full_access);
    let mut w = JsonByteWriter::with_capacity(estimated);
    stream_get_block_full_value_into(source, fetched, config, &mut w).await?;
    Ok(w.into_inner())
}

async fn stream_get_block_full_value_into(
    source: &WorkerSource,
    fetched: &FetchedHotBlock,
    config: GetBlockConfig,
    w: &mut JsonByteWriter,
) -> std::result::Result<(), String> {
    let started = now_ms();
    let start_len = w.len();
    let full_access = fetched
        .access
        .as_ref()
        .and_then(FetchedAccess::full)
        .ok_or_else(|| "streamed full getBlock path requires full block access".to_string())?;
    let access = fetched
        .access
        .as_ref()
        .ok_or_else(|| "streamed full getBlock path requires block access".to_string())?;
    let mut resolver = Resolver::new(source, Some(full_access));

    write_block_header_fields(w, fetched, access);
    if config.rewards {
        w.raw(b",\"rewards\":");
        stream_rewards_value(w, &mut resolver, fetched.block.header.rewards.as_ref()).await?;
        stream_reward_partitions(w, fetched.block.header.rewards.as_ref());
    }
    w.raw(b",\"transactions\":[");

    let mut signature_index = 0usize;
    for (index, row) in fetched.block.tx_rows.iter().enumerate() {
        if index > 0 {
            w.raw(b",");
        }
        stream_full_transaction_entry(
            w,
            &mut resolver,
            fetched,
            row,
            &mut signature_index,
            config.rewards,
        )
        .await?;
        if index & 0x3f == 0x3f || w.pending_bytes() >= JSON_STREAM_CHUNK_BYTES {
            w.flush_chunk_async().await?;
        }
    }

    w.raw(b"]}");
    let detail = format!(
        "full capacity={} slack={}",
        w.capacity(),
        w.capacity()
            .saturating_sub(w.len().saturating_sub(start_len))
    );
    source.record_elapsed(
        "render_streamed_get_block",
        started,
        w.len().saturating_sub(start_len) as u64,
        detail,
        None,
    );
    Ok(())
}

async fn stream_get_block_accounts_value_into(
    source: &WorkerSource,
    fetched: &FetchedHotBlock,
    config: GetBlockConfig,
    w: &mut JsonByteWriter,
) -> std::result::Result<(), String> {
    let started = now_ms();
    let start_len = w.len();
    let full_access = fetched
        .access
        .as_ref()
        .and_then(FetchedAccess::full)
        .ok_or_else(|| "streamed accounts getBlock path requires full block access".to_string())?;
    let access = fetched
        .access
        .as_ref()
        .ok_or_else(|| "streamed accounts getBlock path requires block access".to_string())?;
    let mut resolver = Resolver::new(source, Some(full_access));

    write_block_header_fields(w, fetched, access);
    if config.rewards {
        w.raw(b",\"rewards\":");
        stream_rewards_value(w, &mut resolver, fetched.block.header.rewards.as_ref()).await?;
        stream_reward_partitions(w, fetched.block.header.rewards.as_ref());
    }
    w.raw(b",\"transactions\":[");

    let mut signature_index = 0usize;
    for (index, row) in fetched.block.tx_rows.iter().enumerate() {
        if index > 0 {
            w.raw(b",");
        }
        stream_accounts_transaction_entry(
            w,
            &mut resolver,
            fetched,
            row,
            &mut signature_index,
            config.rewards,
        )
        .await?;
        if index & 0x3f == 0x3f || w.pending_bytes() >= JSON_STREAM_CHUNK_BYTES {
            w.flush_chunk_async().await?;
        }
    }

    w.raw(b"]}");
    let detail = format!(
        "accounts capacity={} slack={}",
        w.capacity(),
        w.capacity()
            .saturating_sub(w.len().saturating_sub(start_len))
    );
    source.record_elapsed(
        "render_streamed_get_block",
        started,
        w.len().saturating_sub(start_len) as u64,
        detail,
        None,
    );
    Ok(())
}

fn full_json_capacity_hint(
    fetched: &FetchedHotBlock,
    full_access: &ArchiveV2BlockAccessBlob,
) -> usize {
    fetched
        .decoded_len
        .saturating_mul(7)
        .saturating_add(full_access.signatures.len().saturating_mul(2))
        .saturating_add(fetched.block.tx_rows.len().saturating_mul(256))
        .saturating_add(4096)
}

async fn stream_get_block_lite_value(
    source: &WorkerSource,
    fetched: &FetchedHotBlock,
    config: GetBlockConfig,
) -> std::result::Result<Vec<u8>, String> {
    let started = now_ms();
    let full_access = fetched
        .access
        .as_ref()
        .and_then(FetchedAccess::full)
        .ok_or_else(|| "streamed lite block route requires full block access".to_string())?;
    let access = fetched
        .access
        .as_ref()
        .ok_or_else(|| "streamed lite block route requires block access".to_string())?;
    let estimated = fetched
        .decoded_len
        .saturating_add(full_access.signatures.len().saturating_mul(2))
        .saturating_add(4096);
    let mut w = JsonByteWriter::with_capacity(estimated);
    let mut resolver = Resolver::new(source, Some(full_access));

    write_block_header_fields(&mut w, fetched, access);
    if config.rewards {
        w.raw(b",\"rewards\":");
        stream_rewards_value(&mut w, &mut resolver, fetched.block.header.rewards.as_ref()).await?;
        stream_reward_partitions(&mut w, fetched.block.header.rewards.as_ref());
    }
    w.raw(b",\"transactions\":[");

    let mut signature_index = 0usize;
    for (index, row) in fetched.block.tx_rows.iter().enumerate() {
        if index > 0 {
            w.raw(b",");
        }
        stream_lite_transaction_entry(&mut w, &mut resolver, fetched, row, &mut signature_index)
            .await?;
    }

    w.raw(b"]}");
    let out = w.into_inner();
    source.record_elapsed(
        "render_streamed_route_block",
        started,
        out.len() as u64,
        "lite",
        None,
    );
    Ok(out)
}

fn write_block_header_fields(
    w: &mut JsonByteWriter,
    fetched: &FetchedHotBlock,
    access: &FetchedAccess,
) {
    w.raw(b"{\"blockhash\":");
    w.base58_32(access.blockhash());
    w.raw(b",\"previousBlockhash\":");
    w.base58_32(access.previous_blockhash());
    w.raw(b",\"parentSlot\":");
    w.u64(fetched.block.header.parent_slot);
    w.raw(b",\"blockTime\":");
    w.option_i64(rpc_block_time(fetched.block.header.block_time));
    w.raw(b",\"blockHeight\":");
    w.option_u64(fetched.block.header.block_height);
}

async fn stream_full_transaction_entry(
    w: &mut JsonByteWriter,
    resolver: &mut Resolver<'_>,
    fetched: &FetchedHotBlock,
    row: &ArchiveV2HotTxRow,
    signature_index: &mut usize,
    include_rewards: bool,
) -> std::result::Result<(), String> {
    let mut message = decode_message(&fetched.block, row, fetched.message_schema)?;
    vote_proof::resolve_message(
        &mut message,
        resolver,
        transaction_signature_bytes(fetched, row, *signature_index)?,
    )
    .await?;
    let meta = decode_metadata(&fetched.block, row, fetched.metadata_schema)?;

    w.raw(b"{\"transaction\":{\"signatures\":");
    stream_transaction_signatures(w, fetched, row, signature_index)?;
    w.raw(b",\"message\":");
    stream_message_value(w, resolver, &message, false).await?;
    w.raw(b"},\"meta\":");
    stream_metadata_value(w, resolver, meta.as_ref(), include_rewards).await?;
    w.raw(b",\"version\":");
    stream_message_version_value(w, &message);
    w.raw(b"}");
    Ok(())
}

async fn stream_lite_transaction_entry(
    w: &mut JsonByteWriter,
    resolver: &mut Resolver<'_>,
    fetched: &FetchedHotBlock,
    row: &ArchiveV2HotTxRow,
    signature_index: &mut usize,
) -> std::result::Result<(), String> {
    let mut message = decode_message(&fetched.block, row, fetched.message_schema)?;
    vote_proof::resolve_message(
        &mut message,
        resolver,
        transaction_signature_bytes(fetched, row, *signature_index)?,
    )
    .await?;

    w.raw(b"{\"transaction\":{\"signatures\":");
    stream_transaction_signatures(w, fetched, row, signature_index)?;
    w.raw(b",\"message\":");
    stream_message_value(w, resolver, &message, true).await?;
    w.raw(b"}}");
    Ok(())
}

async fn stream_accounts_transaction_entry(
    w: &mut JsonByteWriter,
    resolver: &mut Resolver<'_>,
    fetched: &FetchedHotBlock,
    row: &ArchiveV2HotTxRow,
    signature_index: &mut usize,
    include_rewards: bool,
) -> std::result::Result<(), String> {
    let message = decode_account_message_lite(&fetched.block, row, fetched.message_schema)?;
    let meta = decode_metadata(&fetched.block, row, fetched.metadata_schema)?;
    let meta_lite = meta.as_ref().map(account_meta_lite_from_compact);

    w.raw(b"{\"transaction\":");
    stream_account_transaction_lite_value(
        w,
        resolver,
        &message,
        meta_lite.as_ref(),
        fetched,
        row,
        signature_index,
    )
    .await?;
    w.raw(b",\"meta\":");
    stream_account_metadata_value(w, resolver, meta.as_ref(), include_rewards).await?;
    w.raw(b",\"version\":");
    stream_account_message_version_value(w, &message.version);
    w.raw(b"}");
    Ok(())
}

async fn stream_account_transaction_lite_value(
    w: &mut JsonByteWriter,
    resolver: &mut Resolver<'_>,
    message: &AccountMessageLite,
    meta: Option<&AccountMetaLite>,
    fetched: &FetchedHotBlock,
    row: &ArchiveV2HotTxRow,
    signature_index: &mut usize,
) -> std::result::Result<(), String> {
    let (loaded_writable, loaded_readonly) = meta
        .map(|meta| {
            (
                meta.loaded_writable_addresses.as_slice(),
                meta.loaded_readonly_addresses.as_slice(),
            )
        })
        .unwrap_or((&[], &[]));
    w.raw(b"{\"accountKeys\":");
    stream_account_key_objects_value(
        resolver,
        w,
        message.header,
        &message.account_keys,
        &message.program_id_indices,
        loaded_writable,
        loaded_readonly,
    )
    .await?;
    w.raw(b",\"signatures\":");
    stream_transaction_signatures(w, fetched, row, signature_index)?;
    w.raw(b"}");
    Ok(())
}

fn transaction_signature_bytes<'a>(
    fetched: &'a FetchedHotBlock,
    row: &ArchiveV2HotTxRow,
    signature_index: usize,
) -> std::result::Result<&'a [u8], String> {
    let access = fetched
        .access
        .as_ref()
        .ok_or_else(|| "transaction has no signature access data".to_string())?;
    let start = signature_index
        .checked_mul(SIGNATURE_BYTES as usize)
        .ok_or_else(|| "signature offset overflow".to_string())?;
    let end = start
        .checked_add(usize::from(row.signature_count) * SIGNATURE_BYTES as usize)
        .ok_or_else(|| "signature end overflow".to_string())?;
    access
        .signatures()
        .get(start..end)
        .ok_or_else(|| "transaction signature window is incomplete".to_string())
}

fn stream_transaction_signatures(
    w: &mut JsonByteWriter,
    fetched: &FetchedHotBlock,
    row: &ArchiveV2HotTxRow,
    signature_index: &mut usize,
) -> std::result::Result<(), String> {
    let access = fetched
        .access
        .as_ref()
        .ok_or_else(|| "streamed transaction signatures require block access".to_string())?;
    let start = signature_index
        .checked_mul(SIGNATURE_BYTES as usize)
        .ok_or_else(|| "signature byte offset overflow".to_string())?;
    let count = usize::from(row.signature_count);
    let byte_len = count
        .checked_mul(SIGNATURE_BYTES as usize)
        .ok_or_else(|| "signature byte count overflow".to_string())?;
    let end = start
        .checked_add(byte_len)
        .ok_or_else(|| "signature byte end overflow".to_string())?;
    let signatures = access
        .signatures()
        .get(start..end)
        .ok_or_else(|| "signature sidecar ended before transaction signatures".to_string())?;

    w.raw(b"[");
    for (index, signature) in signatures
        .chunks_exact(SIGNATURE_BYTES as usize)
        .enumerate()
    {
        if index > 0 {
            w.raw(b",");
        }
        w.base58_64(signature.try_into().expect("checked signature len"));
    }
    w.raw(b"]");
    *signature_index = signature_index
        .checked_add(count)
        .ok_or_else(|| "signature index overflow".to_string())?;
    Ok(())
}

async fn stream_account_key_objects_value(
    resolver: &mut Resolver<'_>,
    w: &mut JsonByteWriter,
    header: blockzilla_compact::CompactMessageHeader,
    keys: &[CompactPubkey],
    program_id_indices: &[u8],
    loaded_writable_addresses: &[CompactPubkey],
    loaded_readonly_addresses: &[CompactPubkey],
) -> std::result::Result<(), String> {
    let required_signatures = header.num_required_signatures as usize;
    let readonly_signed = header.num_readonly_signed_accounts as usize;
    let readonly_unsigned = header.num_readonly_unsigned_accounts as usize;
    let signed_writable = required_signatures.saturating_sub(readonly_signed);
    let unsigned_writable_end = keys.len().saturating_sub(readonly_unsigned);

    w.raw(b"[");
    let mut first = true;
    for (index, key) in keys.iter().enumerate() {
        let signer = index < required_signatures;
        let header_writable = if signer {
            index < signed_writable
        } else {
            index < unsigned_writable_end
        };
        let writable = header_writable
            && u8::try_from(index)
                .ok()
                .is_none_or(|index| !program_id_indices.contains(&index));
        stream_account_key_object(
            w,
            resolver,
            *key,
            signer,
            "transaction",
            writable,
            &mut first,
        )
        .await?;
    }
    for key in loaded_writable_addresses {
        stream_account_key_object(w, resolver, *key, false, "lookupTable", true, &mut first)
            .await?;
    }
    for key in loaded_readonly_addresses {
        stream_account_key_object(w, resolver, *key, false, "lookupTable", false, &mut first)
            .await?;
    }
    w.raw(b"]");
    Ok(())
}

async fn stream_account_key_object(
    w: &mut JsonByteWriter,
    resolver: &mut Resolver<'_>,
    key: CompactPubkey,
    signer: bool,
    source: &str,
    writable: bool,
    first: &mut bool,
) -> std::result::Result<(), String> {
    if !*first {
        w.raw(b",");
    }
    *first = false;
    let pubkey = resolver.resolve_pubkey(key).await?;
    let writable = writable && !is_reserved_readonly_account(&pubkey);
    w.raw(b"{\"pubkey\":");
    w.string(&pubkey)?;
    w.raw(b",\"signer\":");
    w.json_bool(signer);
    w.raw(b",\"source\":");
    w.string(source)?;
    w.raw(b",\"writable\":");
    w.json_bool(writable);
    w.raw(b"}");
    Ok(())
}

fn transaction_config_value(config: &CompactTransactionConfig) -> Value {
    json!({ "computeUnitLimit": config.compute_unit_limit, "heapSize": config.heap_size,
        "loadedAccountsDataSizeLimit": config.loaded_accounts_data_size_limit,
        "priorityFee": config.priority_fee })
}

fn stream_reward_partitions(
    w: &mut JsonByteWriter,
    rewards: Option<&blockzilla_archive_v2::ArchiveV2HotRewards>,
) {
    w.raw(b",\"numRewardPartitions\":");
    w.option_u64(rewards.and_then(|rewards| rewards.num_partitions));
}

async fn stream_message_value(
    w: &mut JsonByteWriter,
    resolver: &mut Resolver<'_>,
    message: &ArchiveV2HotMessagePayload,
    account_objects: bool,
) -> std::result::Result<(), String> {
    match message {
        ArchiveV2HotMessagePayload::Legacy(message) => {
            stream_message_fields_value(
                w,
                resolver,
                message.header,
                &message.account_keys,
                &message.recent_blockhash,
                &message.instructions,
                None,
                account_objects,
                None,
            )
            .await
        }
        ArchiveV2HotMessagePayload::V0(message) => {
            stream_message_fields_value(
                w,
                resolver,
                message.header,
                &message.account_keys,
                &message.recent_blockhash,
                &message.instructions,
                Some(&message.address_table_lookups),
                account_objects,
                None,
            )
            .await
        }
        ArchiveV2HotMessagePayload::V1(message) => {
            stream_message_fields_value(
                w,
                resolver,
                message.header,
                &message.account_keys,
                &message.recent_blockhash,
                &message.instructions,
                None,
                account_objects,
                Some(&message.config),
            )
            .await
        }
    }
}

async fn stream_message_fields_value(
    w: &mut JsonByteWriter,
    resolver: &mut Resolver<'_>,
    header: blockzilla_compact::CompactMessageHeader,
    account_keys: &[CompactPubkey],
    recent_blockhash: &OwnedCompactRecentBlockhash,
    instructions: &[blockzilla_archive_v2::ArchiveV2HotInstruction],
    address_table_lookups: Option<&[OwnedCompactAddressTableLookup]>,
    account_objects: bool,
    transaction_config: Option<&CompactTransactionConfig>,
) -> std::result::Result<(), String> {
    w.raw(b"{\"accountKeys\":");
    if account_objects {
        stream_account_key_objects_value(resolver, w, header, account_keys, &[], &[], &[]).await?;
    } else {
        stream_compact_pubkey_array_value(w, resolver, account_keys).await?;
    }
    w.raw(b",\"instructions\":");
    stream_instruction_array_value(w, resolver, instructions).await?;
    w.raw(b",\"recentBlockhash\":");
    stream_resolved_recent_blockhash_value(w, resolver, recent_blockhash).await?;
    w.raw(b",\"header\":{\"numRequiredSignatures\":");
    w.u64(u64::from(header.num_required_signatures));
    w.raw(b",\"numReadonlySignedAccounts\":");
    w.u64(u64::from(header.num_readonly_signed_accounts));
    w.raw(b",\"numReadonlyUnsignedAccounts\":");
    w.u64(u64::from(header.num_readonly_unsigned_accounts));
    w.raw(b"}");
    if let Some(lookups) = address_table_lookups {
        w.raw(b",\"addressTableLookups\":");
        stream_address_table_lookups_value(w, resolver, lookups).await?;
    }
    if let Some(config) = transaction_config {
        w.raw(b",\"transactionConfig\":");
        w.json(&transaction_config_value(config))?;
    }
    w.raw(b"}");
    Ok(())
}

async fn stream_compact_pubkey_array_value(
    w: &mut JsonByteWriter,
    resolver: &mut Resolver<'_>,
    keys: &[CompactPubkey],
) -> std::result::Result<(), String> {
    w.raw(b"[");
    for (index, key) in keys.iter().enumerate() {
        if index > 0 {
            w.raw(b",");
        }
        stream_resolved_pubkey_value(w, resolver, *key).await?;
    }
    w.raw(b"]");
    Ok(())
}

async fn stream_address_table_lookups_value(
    w: &mut JsonByteWriter,
    resolver: &mut Resolver<'_>,
    lookups: &[OwnedCompactAddressTableLookup],
) -> std::result::Result<(), String> {
    w.raw(b"[");
    for (index, lookup) in lookups.iter().enumerate() {
        if index > 0 {
            w.raw(b",");
        }
        w.raw(b"{\"accountKey\":");
        stream_resolved_pubkey_value(w, resolver, lookup.account_key).await?;
        w.raw(b",\"writableIndexes\":");
        w.u8_array(&lookup.writable_indexes);
        w.raw(b",\"readonlyIndexes\":");
        w.u8_array(&lookup.readonly_indexes);
        w.raw(b"}");
    }
    w.raw(b"]");
    Ok(())
}

async fn stream_instruction_array_value(
    w: &mut JsonByteWriter,
    resolver: &Resolver<'_>,
    instructions: &[blockzilla_archive_v2::ArchiveV2HotInstruction],
) -> std::result::Result<(), String> {
    w.raw(b"[");
    for (index, instruction) in instructions.iter().enumerate() {
        if index > 0 {
            w.raw(b",");
        }
        w.raw(b"{\"programIdIndex\":");
        w.u64(u64::from(instruction.program_id_index));
        w.raw(b",\"accounts\":");
        w.u8_array(&instruction.accounts);
        w.raw(b",\"data\":");
        let data = instruction_data_base58(&instruction.data, Some(resolver))?;
        // Instruction data is base58, so the string is already JSON-safe ASCII.
        w.raw(b"\"");
        w.raw(data.as_bytes());
        w.raw(b"\"");
        w.raw(b",\"stackHeight\":1}");
    }
    w.raw(b"]");
    Ok(())
}

async fn stream_metadata_value(
    w: &mut JsonByteWriter,
    resolver: &mut Resolver<'_>,
    meta: Option<&CompactMetaV1>,
    include_rewards: bool,
) -> std::result::Result<(), String> {
    let Some(meta) = meta else {
        w.raw(b"null");
        return Ok(());
    };

    let decoded_err = meta.err.as_ref();

    w.raw(b"{\"err\":");
    stream_optional_transaction_error(w, decoded_err)?;
    w.raw(b",\"status\":");
    stream_transaction_status(w, decoded_err)?;
    w.raw(b",\"fee\":");
    w.u64(meta.fee);
    w.raw(b",\"preBalances\":");
    w.u64_array(&meta.pre_balances);
    w.raw(b",\"postBalances\":");
    w.u64_array(&meta.post_balances);
    w.raw(b",\"preTokenBalances\":");
    stream_token_balances_value(w, resolver, &meta.pre_token_balances, false).await?;
    w.raw(b",\"postTokenBalances\":");
    stream_token_balances_value(w, resolver, &meta.post_token_balances, false).await?;
    w.raw(b",\"logMessages\":");
    stream_log_messages_value(w, resolver, meta.logs.as_ref()).await?;
    w.raw(b",\"innerInstructions\":");
    stream_inner_instructions_value(w, meta.inner_instructions.as_deref());
    w.raw(b",\"loadedAddresses\":{\"writable\":");
    stream_compact_pubkey_array_value(w, resolver, &meta.loaded_writable_addresses).await?;
    w.raw(b",\"readonly\":");
    stream_compact_pubkey_array_value(w, resolver, &meta.loaded_readonly_addresses).await?;
    w.raw(b"}");
    if let Some(return_data) = &meta.return_data {
        w.raw(b",\"returnData\":");
        stream_return_data_value(w, resolver, return_data).await?;
    }
    w.raw(b",\"rewards\":");
    if include_rewards {
        stream_compact_rewards_value(w, resolver, &meta.rewards).await?;
    } else {
        w.raw(b"null");
    }
    if let Some(value) = meta.compute_units_consumed {
        w.raw(b",\"computeUnitsConsumed\":");
        w.u64(value);
    }
    if let Some(value) = meta.cost_units {
        w.raw(b",\"costUnits\":");
        w.u64(value);
    }
    w.raw(b"}");
    Ok(())
}

async fn stream_return_data_value(
    w: &mut JsonByteWriter,
    resolver: &mut Resolver<'_>,
    return_data: &CompactReturnData,
) -> std::result::Result<(), String> {
    w.raw(b"{\"programId\":");
    stream_resolved_pubkey_value(w, resolver, return_data.program_id).await?;
    w.raw(b",\"data\":[");
    w.string(&BASE64.encode(&return_data.data))?;
    w.raw(br#","base64"]}"#);
    Ok(())
}

async fn stream_account_metadata_value(
    w: &mut JsonByteWriter,
    resolver: &mut Resolver<'_>,
    meta: Option<&CompactMetaV1>,
    include_rewards: bool,
) -> std::result::Result<(), String> {
    let Some(meta) = meta else {
        w.raw(b"null");
        return Ok(());
    };

    let decoded_err = meta.err.as_ref();

    w.raw(b"{\"err\":");
    stream_optional_transaction_error(w, decoded_err)?;
    w.raw(b",\"status\":");
    stream_transaction_status(w, decoded_err)?;
    w.raw(b",\"fee\":");
    w.u64(meta.fee);
    w.raw(b",\"preBalances\":");
    w.u64_array(&meta.pre_balances);
    w.raw(b",\"postBalances\":");
    w.u64_array(&meta.post_balances);
    w.raw(b",\"preTokenBalances\":");
    stream_token_balances_value(w, resolver, &meta.pre_token_balances, false).await?;
    w.raw(b",\"postTokenBalances\":");
    stream_token_balances_value(w, resolver, &meta.post_token_balances, false).await?;
    if include_rewards {
        w.raw(b",\"rewards\":");
        stream_compact_rewards_value(w, resolver, &meta.rewards).await?;
    }
    w.raw(b"}");
    Ok(())
}

async fn stream_token_balances_value(
    w: &mut JsonByteWriter,
    resolver: &mut Resolver<'_>,
    balances: &[blockzilla_compact::CompactTokenBalance],
    ui_amount_null: bool,
) -> std::result::Result<(), String> {
    w.raw(b"[");
    for (index, balance) in balances.iter().enumerate() {
        if index > 0 {
            w.raw(b",");
        }
        stream_token_balance_value(w, resolver, balance, ui_amount_null).await?;
    }
    w.raw(b"]");
    Ok(())
}

async fn stream_token_balance_value(
    w: &mut JsonByteWriter,
    resolver: &mut Resolver<'_>,
    balance: &blockzilla_compact::CompactTokenBalance,
    ui_amount_null: bool,
) -> std::result::Result<(), String> {
    w.raw(b"{\"accountIndex\":");
    w.u64(u64::from(balance.account_index));
    if let Some(mint) = balance.mint {
        w.raw(b",\"mint\":");
        stream_resolved_pubkey_value(w, resolver, mint).await?;
    }
    if let Some(owner) = balance.owner {
        w.raw(b",\"owner\":");
        stream_resolved_pubkey_value(w, resolver, owner).await?;
    }
    if let Some(program_id) = balance.program_id {
        w.raw(b",\"programId\":");
        stream_resolved_pubkey_value(w, resolver, program_id).await?;
    }
    w.raw(b",\"uiTokenAmount\":");
    stream_ui_token_amount_value(w, balance.amount, balance.decimals, ui_amount_null)?;
    w.raw(b"}");
    Ok(())
}

fn stream_ui_token_amount_value(
    w: &mut JsonByteWriter,
    amount: u64,
    decimals: u8,
    _ui_amount_null: bool,
) -> std::result::Result<(), String> {
    let mut buffer = itoa::Buffer::new();
    let digits = buffer.format(amount).as_bytes();
    w.raw(b"{\"amount\":\"");
    w.raw(digits);
    w.raw(b"\",\"decimals\":");
    w.u64(u64::from(decimals));
    w.raw(b",\"uiAmount\":");
    if amount == 0 {
        w.raw(b"null");
    } else {
        w.json(&ui_amount_number(amount, decimals))?;
    }
    w.raw(b",\"uiAmountString\":");
    w.quoted_ui_amount(digits, decimals);
    w.raw(b"}");
    Ok(())
}

async fn stream_log_messages_value(
    w: &mut JsonByteWriter,
    resolver: &mut Resolver<'_>,
    logs: Option<&CompactLogStream>,
) -> std::result::Result<(), String> {
    let Some(logs) = logs else {
        w.raw(b"null");
        return Ok(());
    };
    if let Some(rendered) = render_logs_with_resolver(resolver, logs).await {
        w.json(&rendered)?;
    } else {
        w.raw(b"[]");
    }
    Ok(())
}

async fn render_logs_with_resolver(
    resolver: &mut Resolver<'_>,
    logs: &CompactLogStream,
) -> Option<Vec<String>> {
    let mut out = Vec::with_capacity(logs.events.len());
    let st = &logs.strings;
    let dt = &logs.data;
    let empty_store = KeyStore { keys: Vec::new() };

    for event in &logs.events {
        match event {
            LogEvent::Invoke { program, depth } => out.push(format!(
                "Program {} invoke [{}]",
                resolver.resolve_pubkey(*program).await.ok()?,
                depth
            )),
            LogEvent::BpfInvoke { program } => out.push(format!(
                "Call BPF program {}",
                resolver.resolve_pubkey(*program).await.ok()?
            )),
            LogEvent::Consumed {
                program,
                used,
                limit,
            } => out.push(format!(
                "Program {} consumed {} of {} compute units",
                resolver.resolve_pubkey(*program).await.ok()?,
                used,
                limit
            )),
            LogEvent::BpfConsumed { used, limit } => {
                out.push(format!("BPF program consumed {used} of {limit} units"))
            }
            LogEvent::Success { program } => out.push(format!(
                "Program {} success",
                resolver.resolve_pubkey(*program).await.ok()?
            )),
            LogEvent::BpfSuccess { program } => out.push(format!(
                "BPF program {} success",
                resolver.resolve_pubkey(*program).await.ok()?
            )),
            LogEvent::Failure { program, reason } => out.push(format!(
                "Program {} failed: {}",
                resolver.resolve_pubkey(*program).await.ok()?,
                st.resolve(*reason)
            )),
            LogEvent::BpfFailure { program, reason } => out.push(format!(
                "BPF program {} failed {}",
                resolver.resolve_pubkey(*program).await.ok()?,
                st.resolve(*reason)
            )),
            LogEvent::FailureCustomProgramError { program, code } => out.push(format!(
                "Program {} failed: custom program error: 0x{:x}",
                resolver.resolve_pubkey(*program).await.ok()?,
                code
            )),
            LogEvent::BpfFailureCustomProgramError { program, code } => out.push(format!(
                "BPF program {} failed custom program error: 0x{:x}",
                resolver.resolve_pubkey(*program).await.ok()?,
                code
            )),
            LogEvent::FailureInvalidAccountData { program } => out.push(format!(
                "Program {} failed: invalid account data for instruction",
                resolver.resolve_pubkey(*program).await.ok()?
            )),
            LogEvent::BpfFailureInvalidAccountData { program } => out.push(format!(
                "BPF program {} failed invalid account data for instruction",
                resolver.resolve_pubkey(*program).await.ok()?
            )),
            LogEvent::FailureInvalidProgramArgument { program } => out.push(format!(
                "Program {} failed: invalid program argument",
                resolver.resolve_pubkey(*program).await.ok()?
            )),
            LogEvent::BpfFailureInvalidProgramArgument { program } => out.push(format!(
                "BPF program {} failed invalid program argument",
                resolver.resolve_pubkey(*program).await.ok()?
            )),
            LogEvent::FailedToComplete { reason } => {
                out.push(format!("Program failed to complete: {}", st.resolve(*reason)))
            }
            LogEvent::LogTruncated => out.push("Log truncated".to_string()),
            LogEvent::StakeMergingAccounts => out.push("Merging stake accounts".to_string()),
            LogEvent::LoaderUpgradedProgram { program } => out.push(format!(
                "Upgraded program {}",
                resolver.resolve_pubkey(*program).await.ok()?
            )),
            LogEvent::LoaderFinalizedAccount { account } => out.push(format!(
                "Finalized account {}",
                resolver.resolve_pubkey(*account).await.ok()?
            )),
            LogEvent::ProgramLog(log) => {
                let payload = render_program_log_without_pubkey_store(log, &empty_store, st)?;
                if payload.is_empty() {
                    out.push("Program log:".to_string());
                } else {
                    out.push(format!("Program log: {payload}"));
                }
            }
            LogEvent::ProgramLogError { msg } => {
                out.push(format!("Program log: Error: {}", st.resolve(*msg)))
            }
            LogEvent::ProgramIdLog { program, log } => {
                let program = resolver.resolve_pubkey(*program).await.ok()?;
                let payload = render_program_log_without_pubkey_store(log, &empty_store, st)?;
                if payload.is_empty() {
                    out.push(format!("Program {program} log:"));
                } else {
                    out.push(format!("Program {program} log: {payload}"));
                }
            }
            LogEvent::ProgramPlainLog(log) => {
                out.push(render_program_log_without_pubkey_store(log, &empty_store, st)?)
            }
            LogEvent::ProgramAccountNotWritable => {
                out.push("Program account not writeable".to_string())
            }
            LogEvent::ProgramNotUpgradeable => out.push("Program not upgradeable".to_string()),
            LogEvent::ProgramAndProgramDataAccountMismatch => {
                out.push("Program and ProgramData account mismatch".to_string())
            }
            LogEvent::ProgramWasExtendedInThisBlockAlready => {
                out.push("Program was extended in this block already".to_string())
            }
            LogEvent::CustomProgramError { code } => {
                out.push(format!("custom program error: 0x{:x}", code))
            }
            LogEvent::Return { program, data } => out.push(format!(
                "Program return: {} {}",
                resolver.resolve_pubkey(*program).await.ok()?,
                dt.render(*data),
            )),
            LogEvent::Data { data } => out.push(format!("Program data: {}", dt.render(*data))),
            LogEvent::Consumption { units } => {
                out.push(format!("Program consumption: {} units remaining", units))
            }
            LogEvent::CbRequestUnits { units } => out.push(format!(
                "Program ComputeBudget111111111111111111111111111111 request units {}",
                units
            )),
            LogEvent::ProgramNotDeployed { program } => {
                if let Some(program) = program {
                    out.push(format!(
                        "Program {} is not deployed",
                        resolver.resolve_pubkey(*program).await.ok()?
                    ));
                } else {
                    out.push("Program is not deployed".to_string());
                }
            }
            LogEvent::ProgramNotCached { program } => {
                if let Some(program) = program {
                    out.push(format!(
                        "Program {} is not cached",
                        resolver.resolve_pubkey(*program).await.ok()?
                    ));
                } else {
                    out.push("Program is not cached".to_string());
                }
            }
            LogEvent::UnknownProgram { program } => {
                out.push(format!("Unknown program {}", st.resolve(*program)))
            }
            LogEvent::UnknownAccount { account } => out.push(format!(
                "Instruction references an unknown account {}",
                st.resolve(*account)
            )),
            LogEvent::VerifyEd25519 => out.push("VerifyEd25519".to_string()),
            LogEvent::VerifySecp256k1 => out.push("VerifySecp256k1".to_string()),
            LogEvent::RuntimeWritablePrivilegeEscalated { account } => out.push(format!(
                "{}'s writable privilege escalated",
                resolver.resolve_pubkey(*account).await.ok()?
            )),
            LogEvent::RuntimeSignerPrivilegeEscalated { account } => out.push(format!(
                "{}'s signer privilege escalated",
                resolver.resolve_pubkey(*account).await.ok()?
            )),
            LogEvent::RuntimeAccountOwnerBalanceVerificationFailed { account } => out.push(format!(
                "failed to verify account {} instruction spent from the balance of an account it does not own",
                resolver.resolve_pubkey(*account).await.ok()?
            )),
            LogEvent::CloseContextState => out.push("CloseContextState".to_string()),
            LogEvent::Plain { text } | LogEvent::Unparsed { text } => {
                out.push(st.resolve(*text).to_string())
            }
            LogEvent::ProgramIdMismatch => out.push("Program id mismatch".to_string()),
            LogEvent::System(system_log) => {
                out.push(render_system_log_without_pubkey_store(system_log, st)?)
            }
        }
    }

    Some(apply_log_messages_byte_limit(out))
}

fn apply_log_messages_byte_limit(messages: Vec<String>) -> Vec<String> {
    let mut out = Vec::with_capacity(messages.len());
    let mut bytes_written = 0usize;
    let mut limit_warning = false;

    for message in messages {
        let next_bytes_written = bytes_written.saturating_add(message.len());
        if next_bytes_written >= LOG_MESSAGES_BYTES_LIMIT {
            if !limit_warning {
                limit_warning = true;
                out.push("Log truncated".to_string());
            }
        } else {
            bytes_written = next_bytes_written;
            out.push(message);
        }
    }

    out
}

fn render_program_log_without_pubkey_store(
    log: &ProgramLog,
    empty_store: &KeyStore,
    strings: &blockzilla_primitives::StringTable,
) -> Option<String> {
    if let ProgramLog::Memo(
        blockzilla_program_logs::program_logs::memo::MemoLog::MemoLenAndDebug { len, memo },
    ) = log
    {
        let memo = strings.resolve(*memo);
        let memo = if memo.starts_with('"') && memo.ends_with('"') {
            memo.to_string()
        } else {
            format!("{memo:?}")
        };
        return Some(format!("Memo (len {}): {}", strings.resolve(*len), memo));
    }
    Some(program_logs::render_program_log(log, empty_store, strings))
}

fn render_system_log_without_pubkey_store(
    log: &blockzilla_program_logs::program_logs::system_program::SystemProgramLog,
    strings: &blockzilla_primitives::StringTable,
) -> Option<String> {
    use blockzilla_program_logs::{
        program_logs::system_program::SystemInstructionLog,
        program_logs::system_program::SystemProgramLog,
    };

    Some(match log {
        SystemProgramLog::Instruction(instruction) => match instruction {
            SystemInstructionLog::RevokePendingActivation => {
                "Instruction: RevokePendingActivation".to_string()
            }
        },
        SystemProgramLog::AllocateRequestedTooLarge {
            requested,
            max_allowed,
        } => format!(
            "Allocate: requested {}, max allowed {}",
            requested, max_allowed
        ),
        SystemProgramLog::TransferFromMustNotCarryData => {
            "Transfer: `from` must not carry data".to_string()
        }
        SystemProgramLog::CreateAccountDataSizeLimitedInInnerInstructions { limit } => format!(
            "SystemProgram::CreateAccount data size limited to {} in inner instructions",
            limit
        ),
        SystemProgramLog::TransferInsufficient { have, need } => {
            format!("Transfer: insufficient lamports {}, need {}", have, need)
        }
        SystemProgramLog::AdvanceNonceRecentBlockhashesEmpty => {
            "Advance nonce account: recent blockhash list is empty".to_string()
        }
        SystemProgramLog::InitializeNonceRecentBlockhashesEmpty => {
            "Initialize nonce account: recent blockhash list is empty".to_string()
        }
        SystemProgramLog::AuthorizeNonceAccount { msg } => {
            format!("Authorize nonce account: {}", strings.resolve(*msg))
        }
        SystemProgramLog::NonceInsufficientLamports { action, have, need } => format!(
            "{} nonce account: insufficient lamports {}, need {}",
            nonce_action_name(*action),
            have,
            need
        ),
        SystemProgramLog::NonceCanOnlyAdvanceOncePerSlot { action } => format!(
            "{} nonce account: nonce can only advance once per slot",
            nonce_action_name(*action)
        ),
        _ => return None,
    })
}

fn nonce_action_name(
    action: blockzilla_program_logs::program_logs::system_program::NonceAction,
) -> &'static str {
    use blockzilla_program_logs::program_logs::system_program::NonceAction;

    match action {
        NonceAction::Advance => "Advance",
        NonceAction::Withdraw => "Withdraw",
        NonceAction::Initialize => "Initialize",
        NonceAction::Authorize => "Authorize",
    }
}

fn stream_inner_instructions_value(
    w: &mut JsonByteWriter,
    inner_instructions: Option<&[CompactInnerInstructions]>,
) {
    let Some(inner_instructions) = inner_instructions else {
        w.raw(b"null");
        return;
    };
    w.raw(b"[");
    for (index, group) in inner_instructions.iter().enumerate() {
        if index > 0 {
            w.raw(b",");
        }
        w.raw(b"{\"index\":");
        w.u64(u64::from(group.index));
        w.raw(b",\"instructions\":[");
        for (instruction_index, instruction) in group.instructions.iter().enumerate() {
            if instruction_index > 0 {
                w.raw(b",");
            }
            w.raw(b"{\"programIdIndex\":");
            w.u64(u64::from(instruction.program_id_index));
            w.raw(b",\"accounts\":");
            w.u8_array(&instruction.accounts);
            w.raw(b",\"data\":");
            let data = base58_bytes(&instruction.data);
            w.raw(b"\"");
            w.raw(data.as_bytes());
            w.raw(b"\"");
            w.raw(b",\"stackHeight\":");
            w.option_u64(instruction.stack_height.map(u64::from));
            w.raw(b"}");
        }
        w.raw(b"]}");
    }
    w.raw(b"]");
}

async fn stream_compact_rewards_value(
    w: &mut JsonByteWriter,
    resolver: &mut Resolver<'_>,
    rewards: &[CompactReward],
) -> std::result::Result<(), String> {
    if rewards.is_empty() {
        w.raw(b"[]");
        return Ok(());
    }
    w.raw(b"[");
    for (index, reward) in rewards.iter().enumerate() {
        if index > 0 {
            w.raw(b",");
        }
        stream_compact_reward_value(w, resolver, reward).await?;
    }
    w.raw(b"]");
    Ok(())
}

async fn stream_compact_reward_value(
    w: &mut JsonByteWriter,
    resolver: &mut Resolver<'_>,
    reward: &CompactReward,
) -> std::result::Result<(), String> {
    w.raw(b"{\"pubkey\":");
    stream_resolved_pubkey_value(w, resolver, reward.pubkey).await?;
    w.raw(b",\"lamports\":");
    w.i64(reward.lamports);
    w.raw(b",\"postBalance\":");
    w.u64(reward.post_balance);
    w.raw(b",\"rewardType\":");
    match reward.reward_type {
        1 => w.raw(br#""Fee""#),
        2 => w.raw(br#""Rent""#),
        3 => w.raw(br#""Staking""#),
        4 => w.raw(br#""Voting""#),
        _ => w.raw(b"null"),
    }
    w.raw(b",\"commission\":");
    w.option_u8(reward.commission);
    w.raw(b"}");
    Ok(())
}

fn stream_account_metadata_lite_value(
    w: &mut JsonByteWriter,
    meta: Option<&AccountMetaLite>,
    include_rewards: bool,
) -> std::result::Result<(), String> {
    let Some(meta) = meta else {
        w.raw(b"null");
        return Ok(());
    };

    let decoded_err = meta.err.as_ref();

    w.raw(b"{\"err\":");
    stream_optional_transaction_error(w, decoded_err)?;
    w.raw(b",\"status\":");
    stream_transaction_status(w, decoded_err)?;
    w.raw(b",\"fee\":");
    w.u64(meta.fee);
    w.raw(b",\"preBalances\":");
    w.u64_array(&meta.pre_balances);
    w.raw(b",\"postBalances\":");
    w.u64_array(&meta.post_balances);
    w.raw(b",\"preTokenBalances\":");
    stream_token_balances_lite_value(w, meta.pre_token_balance_count);
    w.raw(b",\"postTokenBalances\":");
    stream_token_balances_lite_value(w, meta.post_token_balance_count);
    if include_rewards {
        w.raw(b",\"rewards\":null");
    }
    w.raw(b"}");
    Ok(())
}

fn stream_token_balances_lite_value(w: &mut JsonByteWriter, count: usize) {
    if count == 0 {
        w.raw(b"null");
    } else {
        w.raw(b"[]");
    }
}

async fn stream_rewards_value(
    w: &mut JsonByteWriter,
    resolver: &mut Resolver<'_>,
    rewards: Option<&blockzilla_archive_v2::ArchiveV2HotRewards>,
) -> std::result::Result<(), String> {
    let Some(rewards) = rewards else {
        w.raw(b"null");
        return Ok(());
    };

    w.raw(b"[");
    for (index, reward) in rewards.decoded.iter().enumerate() {
        if index > 0 {
            w.raw(b",");
        }
        w.raw(b"{\"pubkey\":");
        stream_resolved_pubkey_value(w, resolver, reward.pubkey).await?;
        w.raw(b",\"lamports\":");
        w.i64(reward.lamports);
        w.raw(b",\"postBalance\":");
        w.u64(reward.post_balance);
        w.raw(b",\"rewardType\":");
        match reward.reward_type {
            1 => w.raw(br#""Fee""#),
            2 => w.raw(br#""Rent""#),
            3 => w.raw(br#""Staking""#),
            4 => w.raw(br#""Voting""#),
            _ => w.raw(b"null"),
        }
        w.raw(b",\"commission\":");
        w.option_u8(reward.commission);
        w.raw(b"}");
        if index & 0x3ff == 0x3ff {
            w.flush_chunk_async().await?;
        }
    }
    w.raw(b"]");
    Ok(())
}

fn stream_message_version_value(w: &mut JsonByteWriter, message: &ArchiveV2HotMessagePayload) {
    match message {
        ArchiveV2HotMessagePayload::Legacy(_) => w.raw(br#""legacy""#),
        ArchiveV2HotMessagePayload::V0(_) => w.raw(b"0"),
        ArchiveV2HotMessagePayload::V1(_) => w.raw(b"1"),
    }
}

fn stream_account_message_version_value(w: &mut JsonByteWriter, version: &AccountMessageVersion) {
    match version {
        AccountMessageVersion::Legacy => w.raw(br#""legacy""#),
        AccountMessageVersion::V0 => w.raw(b"0"),
        AccountMessageVersion::V1 => w.raw(b"1"),
    }
}

async fn account_transactions_value(
    resolver: &mut Resolver<'_>,
    fetched: &FetchedHotBlock,
    include_rewards: bool,
) -> std::result::Result<Value, String> {
    let started = now_ms();
    let signatures = resolver.read_block_signatures(&fetched.row).await?;
    let mut signature_index = 0usize;
    let mut out = Vec::with_capacity(fetched.block.tx_rows.len());
    for row in &fetched.block.tx_rows {
        let tx_signatures =
            take_signatures(&signatures, &mut signature_index, row.signature_count)?;
        let message = decode_account_message_lite(&fetched.block, row, fetched.message_schema)?;
        let meta = decode_metadata(&fetched.block, row, fetched.metadata_schema)?;
        let meta_lite = meta.as_ref().map(account_meta_lite_from_compact);
        out.push(json!({
            "transaction": account_transaction_lite_value(resolver, &message, meta_lite.as_ref(), tx_signatures).await?,
            "meta": account_metadata_value(resolver, meta.as_ref(), include_rewards).await?,
            "version": message.version.value(),
        }));
    }
    resolver.source.record_elapsed(
        "render_transactions",
        started,
        0,
        "account_transactions",
        None,
    );
    Ok(Value::Array(out))
}

struct AccountMessageLite {
    header: blockzilla_compact::CompactMessageHeader,
    account_keys: Vec<CompactPubkey>,
    program_id_indices: Vec<u8>,
    version: AccountMessageVersion,
}

#[derive(Clone, Copy)]
enum AccountMessageVersion {
    Legacy,
    V0,
    V1,
}

impl AccountMessageVersion {
    fn value(&self) -> Value {
        match self {
            Self::Legacy => Value::String("legacy".to_string()),
            Self::V0 => Value::from(0),
            Self::V1 => Value::from(1),
        }
    }
}

struct AccountMetaLite {
    err: Option<StoredTransactionError>,
    fee: u64,
    pre_balances: Vec<u64>,
    post_balances: Vec<u64>,
    pre_token_balance_count: usize,
    post_token_balance_count: usize,
    loaded_writable_addresses: Vec<CompactPubkey>,
    loaded_readonly_addresses: Vec<CompactPubkey>,
}

fn account_meta_lite_from_compact(meta: &CompactMetaV1) -> AccountMetaLite {
    AccountMetaLite {
        err: meta.err.clone(),
        fee: meta.fee,
        pre_balances: meta.pre_balances.clone(),
        post_balances: meta.post_balances.clone(),
        pre_token_balance_count: meta.pre_token_balances.len(),
        post_token_balance_count: meta.post_token_balances.len(),
        loaded_writable_addresses: meta.loaded_writable_addresses.clone(),
        loaded_readonly_addresses: meta.loaded_readonly_addresses.clone(),
    }
}

async fn transactions_value(
    resolver: &mut Resolver<'_>,
    fetched: &FetchedHotBlock,
    lite: bool,
    include_meta: bool,
) -> std::result::Result<Value, String> {
    let started = now_ms();
    let signatures = resolver.read_block_signatures(&fetched.row).await?;
    let mut signature_index = 0usize;
    let mut out = Vec::with_capacity(fetched.block.tx_rows.len());
    for row in &fetched.block.tx_rows {
        let tx_signatures =
            take_signatures(&signatures, &mut signature_index, row.signature_count)?;
        let mut message = decode_message(&fetched.block, row, fetched.message_schema)?;
        vote_proof::resolve_message(
            &mut message,
            resolver,
            transaction_signature_bytes(
                fetched,
                row,
                signature_index - usize::from(row.signature_count),
            )?,
        )
        .await?;
        let transaction =
            transaction_value(resolver, &message, tx_signatures, !include_meta).await?;
        if lite {
            out.push(json!({ "transaction": transaction }));
            continue;
        }
        let meta = if include_meta {
            decode_metadata(&fetched.block, row, fetched.metadata_schema)?
        } else {
            None
        };
        out.push(json!({
            "transaction": transaction,
            "meta": metadata_value(resolver, meta.as_ref()).await?,
            "version": message_version_value(&message),
        }));
    }
    resolver
        .source
        .record_elapsed("render_transactions", started, 0, "transactions", None);
    Ok(Value::Array(out))
}

async fn account_transaction_value(
    resolver: &mut Resolver<'_>,
    message: &ArchiveV2HotMessagePayload,
    meta: Option<&CompactMetaV1>,
    signatures: Vec<String>,
) -> std::result::Result<Value, String> {
    let account_keys = match message {
        ArchiveV2HotMessagePayload::Legacy(message) => {
            let program_id_indices = message_program_id_indices(&message.instructions);
            let (loaded_writable, loaded_readonly) = meta
                .map(|meta| {
                    (
                        meta.loaded_writable_addresses.as_slice(),
                        meta.loaded_readonly_addresses.as_slice(),
                    )
                })
                .unwrap_or((&[], &[]));
            account_key_objects_value(
                resolver,
                message.header,
                &message.account_keys,
                &program_id_indices,
                loaded_writable,
                loaded_readonly,
            )
            .await?
        }
        ArchiveV2HotMessagePayload::V0(message) => {
            let program_id_indices = message_program_id_indices(&message.instructions);
            let (loaded_writable, loaded_readonly) = meta
                .map(|meta| {
                    (
                        meta.loaded_writable_addresses.as_slice(),
                        meta.loaded_readonly_addresses.as_slice(),
                    )
                })
                .unwrap_or((&[], &[]));
            account_key_objects_value(
                resolver,
                message.header,
                &message.account_keys,
                &program_id_indices,
                loaded_writable,
                loaded_readonly,
            )
            .await?
        }
        ArchiveV2HotMessagePayload::V1(message) => {
            let program_id_indices = message_program_id_indices(&message.instructions);
            account_key_objects_value(
                resolver,
                message.header,
                &message.account_keys,
                &program_id_indices,
                &[],
                &[],
            )
            .await?
        }
    };
    Ok(json!({
        "accountKeys": account_keys,
        "signatures": signatures,
    }))
}

async fn account_transaction_lite_value(
    resolver: &mut Resolver<'_>,
    message: &AccountMessageLite,
    meta: Option<&AccountMetaLite>,
    signatures: Vec<String>,
) -> std::result::Result<Value, String> {
    let (loaded_writable, loaded_readonly) = meta
        .map(|meta| {
            (
                meta.loaded_writable_addresses.as_slice(),
                meta.loaded_readonly_addresses.as_slice(),
            )
        })
        .unwrap_or((&[], &[]));
    Ok(json!({
        "accountKeys": account_key_objects_value(
            resolver,
            message.header,
            &message.account_keys,
            &message.program_id_indices,
            loaded_writable,
            loaded_readonly,
        ).await?,
        "signatures": signatures,
    }))
}

fn take_signatures(
    signatures: &[String],
    index: &mut usize,
    count: u8,
) -> std::result::Result<Vec<String>, String> {
    let start = *index;
    let end = start
        .checked_add(usize::from(count))
        .ok_or_else(|| "signature index overflow".to_string())?;
    let values = signatures
        .get(start..end)
        .ok_or_else(|| "signature sidecar ended before block row signatures".to_string())?
        .to_vec();
    *index = end;
    Ok(values)
}

async fn signatures_value(
    resolver: &Resolver<'_>,
    fetched: &FetchedHotBlock,
) -> std::result::Result<Value, String> {
    let started = now_ms();
    if let Some(access) = fetched.access.as_ref() {
        let mut signature_index = 0usize;
        let mut out = Vec::with_capacity(fetched.block.tx_rows.len());
        for row in &fetched.block.tx_rows {
            if row.signature_count > 0 {
                let start = signature_index
                    .checked_mul(SIGNATURE_BYTES as usize)
                    .ok_or_else(|| "signature byte offset overflow".to_string())?;
                let end = start
                    .checked_add(SIGNATURE_BYTES as usize)
                    .ok_or_else(|| "signature byte end overflow".to_string())?;
                let signature = access.signatures().get(start..end).ok_or_else(|| {
                    "signature sidecar ended before first transaction signature".to_string()
                })?;
                out.push(Value::String(base58_64(
                    signature.try_into().expect("checked signature len"),
                )));
            }
            signature_index = signature_index
                .checked_add(usize::from(row.signature_count))
                .ok_or_else(|| "signature index overflow".to_string())?;
        }
        resolver
            .source
            .record_elapsed("render_signatures", started, 0, "signatures", None);
        return Ok(Value::Array(out));
    }

    let signatures = resolver.read_block_signatures(&fetched.row).await?;
    let mut index = 0usize;
    let mut out = Vec::with_capacity(fetched.block.tx_rows.len());
    for row in &fetched.block.tx_rows {
        if row.signature_count == 0 {
            continue;
        }
        let signature = signatures
            .get(index)
            .ok_or_else(|| {
                "signature sidecar ended before first transaction signature".to_string()
            })?
            .clone();
        out.push(Value::String(signature));
        index += usize::from(row.signature_count);
    }
    resolver
        .source
        .record_elapsed("render_signatures", started, 0, "signatures", None);
    Ok(Value::Array(out))
}

fn decode_message(
    block: &ArchiveV2HotBlockBlob,
    row: &ArchiveV2HotTxRow,
    schema: MessageSchema,
) -> std::result::Result<ArchiveV2HotMessagePayload, String> {
    if row.flags & ARCHIVE_V2_TX_FLAG_TX_RAW_FALLBACK != 0 {
        return Err(format!(
            "tx_index {} has an unsupported raw transaction",
            row.tx_index
        ));
    }
    let bytes = region_slice(
        &block.message_bytes,
        row.message_offset,
        row.message_len,
        "message",
        row.tx_index,
    )?;
    crate::archive_schema::decode_message(schema, bytes)
        .map_err(|err| format!("decode message tx_index {}: {err}", row.tx_index))
}

fn decode_metadata(
    block: &ArchiveV2HotBlockBlob,
    row: &ArchiveV2HotTxRow,
    schema: MetadataSchema,
) -> std::result::Result<Option<CompactMetaV1>, String> {
    if row.flags & ARCHIVE_V2_TX_FLAG_HAS_METADATA == 0 {
        return Ok(None);
    }
    if row.flags & ARCHIVE_V2_TX_FLAG_METADATA_RAW_FALLBACK != 0 {
        return Err(format!(
            "tx_index {} has unsupported raw execution metadata",
            row.tx_index
        ));
    }
    let bytes = region_slice(
        &block.metadata_bytes,
        row.metadata_offset,
        row.metadata_len,
        "metadata",
        row.tx_index,
    )?;
    crate::archive_schema::decode_metadata(schema, bytes)
        .map(Some)
        .map_err(|err| format!("decode metadata tx_index {}: {err}", row.tx_index))
}

fn decode_account_message_lite(
    block: &ArchiveV2HotBlockBlob,
    row: &ArchiveV2HotTxRow,
    schema: MessageSchema,
) -> std::result::Result<AccountMessageLite, String> {
    let message = decode_message(block, row, schema)?;
    let version = match &message {
        ArchiveV2HotMessagePayload::Legacy(_) => AccountMessageVersion::Legacy,
        ArchiveV2HotMessagePayload::V0(_) => AccountMessageVersion::V0,
        ArchiveV2HotMessagePayload::V1(_) => AccountMessageVersion::V1,
    };
    let (header, account_keys, instructions) = match message {
        ArchiveV2HotMessagePayload::Legacy(message) => {
            (message.header, message.account_keys, message.instructions)
        }
        ArchiveV2HotMessagePayload::V0(message) => {
            (message.header, message.account_keys, message.instructions)
        }
        ArchiveV2HotMessagePayload::V1(message) => {
            (message.header, message.account_keys, message.instructions)
        }
    };
    Ok(AccountMessageLite {
        header,
        account_keys,
        program_id_indices: message_program_id_indices(&instructions),
        version,
    })
}

fn decode_account_message_lite_bytes(
    bytes: &[u8],
    tx_index: u32,
) -> std::result::Result<AccountMessageLite, String> {
    let mut reader = bytes;
    let variant: u32 = read_wincode_value(&mut reader).map_err(|err| {
        format!(
            "decode accounts message variant tx_index {}: {err}",
            tx_index
        )
    })?;
    let version = match variant {
        0 => AccountMessageVersion::Legacy,
        1 => AccountMessageVersion::V0,
        2 => AccountMessageVersion::V1,
        _ => {
            return Err(format!(
                "decode accounts message tx_index {}: unsupported message variant {}",
                tx_index, variant
            ));
        }
    };
    let header = read_wincode_value(&mut reader).map_err(|err| {
        format!(
            "decode accounts message header tx_index {}: {err}",
            tx_index
        )
    })?;
    if matches!(version, AccountMessageVersion::V1) {
        let _config: CompactTransactionConfig = read_wincode_value(&mut reader).map_err(|err| {
            format!(
                "decode accounts message config tx_index {}: {err}",
                tx_index
            )
        })?;
    }
    let account_keys = read_wincode_value(&mut reader)
        .map_err(|err| format!("decode accounts message keys tx_index {}: {err}", tx_index))?;
    let _recent_blockhash: OwnedCompactRecentBlockhash =
        read_wincode_value(&mut reader).map_err(|err| {
            format!(
                "decode accounts message recent blockhash tx_index {}: {err}",
                tx_index
            )
        })?;
    let instructions: Vec<blockzilla_archive_v2::ArchiveV2HotInstruction> =
        read_wincode_value(&mut reader).map_err(|err| {
            format!(
                "decode accounts message instructions tx_index {}: {err}",
                tx_index
            )
        })?;
    let mut program_id_indices = instructions
        .iter()
        .map(|instruction| instruction.program_id_index)
        .collect::<Vec<_>>();
    program_id_indices.sort_unstable();
    program_id_indices.dedup();
    Ok(AccountMessageLite {
        header,
        account_keys,
        program_id_indices,
        version,
    })
}

fn decode_account_metadata_lite(
    block: &ArchiveV2HotBlockBlob,
    row: &ArchiveV2HotTxRow,
) -> std::result::Result<Option<AccountMetaLite>, String> {
    if row.flags & ARCHIVE_V2_TX_FLAG_HAS_METADATA == 0 || row.metadata_len == 0 {
        return Ok(None);
    }
    if row.flags & ARCHIVE_V2_TX_FLAG_METADATA_RAW_FALLBACK != 0 {
        return Ok(None);
    }
    let bytes = region_slice(
        &block.metadata_bytes,
        row.metadata_offset,
        row.metadata_len,
        "metadata",
        row.tx_index,
    )?;
    decode_account_metadata_lite_bytes(bytes)
        .map(Some)
        .map_err(|err| format!("decode accounts metadata tx_index {}: {err}", row.tx_index))
}

fn decode_account_metadata_lite_bytes(
    bytes: &[u8],
) -> std::result::Result<AccountMetaLite, String> {
    let mut reader = bytes;
    let err = read_wincode_value(&mut reader)?;
    let fee = read_wincode_value(&mut reader)?;
    let pre_balances = read_wincode_value(&mut reader)?;
    let post_balances = read_wincode_value(&mut reader)?;
    skip_option_inner_instructions(&mut reader)?;
    skip_option_log_stream(&mut reader)?;
    let pre_token_balance_count = skip_token_balances(&mut reader)?;
    let post_token_balance_count = skip_token_balances(&mut reader)?;
    skip_rewards(&mut reader)?;
    let loaded_writable_addresses = read_wincode_value(&mut reader)?;
    let loaded_readonly_addresses = read_wincode_value(&mut reader)?;
    skip_option_return_data(&mut reader)?;
    skip_option_u64(&mut reader)?;
    skip_option_u64(&mut reader)?;
    Ok(AccountMetaLite {
        err,
        fee,
        pre_balances,
        post_balances,
        pre_token_balance_count,
        post_token_balance_count,
        loaded_writable_addresses,
        loaded_readonly_addresses,
    })
}

fn read_wincode_value<'de, T>(reader: &mut impl Reader<'de>) -> std::result::Result<T, String>
where
    T: SchemaRead<'de, WincodeLeb128Config, Dst = T>,
{
    T::get(reader.by_ref()).map_err(|err| err.to_string())
}

fn read_wincode_len<'de>(reader: &mut impl Reader<'de>) -> std::result::Result<usize, String> {
    let len: u64 = read_wincode_value(reader)?;
    usize::try_from(len).map_err(|_| "wincode length does not fit usize".to_string())
}

fn skip_raw_bytes<'de>(
    reader: &mut impl Reader<'de>,
    len: usize,
) -> std::result::Result<(), String> {
    reader
        .take_scoped(len)
        .map(|_| ())
        .map_err(|err| err.to_string())
}

fn read_option_tag<'de>(reader: &mut impl Reader<'de>) -> std::result::Result<u8, String> {
    let tag: u8 = read_wincode_value(reader)?;
    match tag {
        0 | 1 => Ok(tag),
        _ => Err(format!("invalid option tag {tag}")),
    }
}

fn skip_option_u8<'de>(reader: &mut impl Reader<'de>) -> std::result::Result<(), String> {
    if read_option_tag(reader)? == 1 {
        let _: u8 = read_wincode_value(reader)?;
    }
    Ok(())
}

fn skip_option_u32<'de>(reader: &mut impl Reader<'de>) -> std::result::Result<(), String> {
    if read_option_tag(reader)? == 1 {
        let _: u32 = read_wincode_value(reader)?;
    }
    Ok(())
}

fn skip_option_u64<'de>(reader: &mut impl Reader<'de>) -> std::result::Result<(), String> {
    if read_option_tag(reader)? == 1 {
        let _: u64 = read_wincode_value(reader)?;
    }
    Ok(())
}

fn skip_byte_vec<'de>(reader: &mut impl Reader<'de>) -> std::result::Result<(), String> {
    let len = read_wincode_len(reader)?;
    skip_raw_bytes(reader, len)
}

fn skip_u32_vec<'de>(reader: &mut impl Reader<'de>) -> std::result::Result<(), String> {
    let len = read_wincode_len(reader)?;
    for _ in 0..len {
        let _: u32 = read_wincode_value(reader)?;
    }
    Ok(())
}

fn skip_option_inner_instructions<'de>(
    reader: &mut impl Reader<'de>,
) -> std::result::Result<(), String> {
    if read_option_tag(reader)? == 1 {
        let len = read_wincode_len(reader)?;
        for _ in 0..len {
            skip_inner_instructions(reader)?;
        }
    }
    Ok(())
}

fn skip_inner_instructions<'de>(reader: &mut impl Reader<'de>) -> std::result::Result<(), String> {
    let _: u32 = read_wincode_value(reader)?;
    let len = read_wincode_len(reader)?;
    for _ in 0..len {
        let _: u32 = read_wincode_value(reader)?;
        skip_byte_vec(reader)?;
        skip_byte_vec(reader)?;
        skip_option_u32(reader)?;
    }
    Ok(())
}

fn skip_option_log_stream<'de>(reader: &mut impl Reader<'de>) -> std::result::Result<(), String> {
    if read_option_tag(reader)? == 1 {
        skip_log_events(reader)?;
        skip_string_table(reader)?;
        skip_data_table(reader)?;
    }
    Ok(())
}

fn skip_log_events<'de>(reader: &mut impl Reader<'de>) -> std::result::Result<(), String> {
    let len = read_wincode_len(reader)?;
    for _ in 0..len {
        let _: blockzilla_compact::LogEvent = read_wincode_value(reader)?;
    }
    Ok(())
}

fn skip_string_table<'de>(reader: &mut impl Reader<'de>) -> std::result::Result<(), String> {
    skip_u32_vec(reader)?;
    skip_byte_vec(reader)
}

fn skip_data_table<'de>(reader: &mut impl Reader<'de>) -> std::result::Result<(), String> {
    let arrays_len = read_wincode_len(reader)?;
    for _ in 0..arrays_len {
        let _: u32 = read_wincode_value(reader)?;
    }
    skip_u32_vec(reader)?;
    skip_byte_vec(reader)
}

fn skip_token_balances<'de>(reader: &mut impl Reader<'de>) -> std::result::Result<usize, String> {
    let len = read_wincode_len(reader)?;
    for _ in 0..len {
        let _: u32 = read_wincode_value(reader)?;
        skip_option_compact_pubkey(reader)?;
        skip_option_compact_pubkey(reader)?;
        skip_option_compact_pubkey(reader)?;
        let _: u64 = read_wincode_value(reader)?;
        let _: u8 = read_wincode_value(reader)?;
    }
    Ok(len)
}

fn skip_rewards<'de>(reader: &mut impl Reader<'de>) -> std::result::Result<(), String> {
    let len = read_wincode_len(reader)?;
    for _ in 0..len {
        skip_compact_pubkey(reader)?;
        let _: i64 = read_wincode_value(reader)?;
        let _: u64 = read_wincode_value(reader)?;
        let _: i32 = read_wincode_value(reader)?;
        skip_option_u8(reader)?;
    }
    Ok(())
}

fn skip_option_return_data<'de>(reader: &mut impl Reader<'de>) -> std::result::Result<(), String> {
    if read_option_tag(reader)? == 1 {
        skip_compact_pubkey(reader)?;
        skip_byte_vec(reader)?;
    }
    Ok(())
}

fn skip_option_compact_pubkey<'de>(
    reader: &mut impl Reader<'de>,
) -> std::result::Result<(), String> {
    if read_option_tag(reader)? == 1 {
        skip_compact_pubkey(reader)?;
    }
    Ok(())
}

fn skip_compact_pubkey<'de>(reader: &mut impl Reader<'de>) -> std::result::Result<(), String> {
    let id: u32 = read_wincode_value(reader)?;
    if id == CompactPubkey::RAW_SENTINEL {
        skip_raw_bytes(reader, 32)?;
    }
    Ok(())
}

async fn transaction_value(
    resolver: &mut Resolver<'_>,
    message: &ArchiveV2HotMessagePayload,
    signatures: Vec<String>,
    account_objects: bool,
) -> std::result::Result<Value, String> {
    Ok(json!({
        "signatures": signatures,
        "message": message_value(resolver, message, account_objects).await?,
    }))
}

async fn message_value(
    resolver: &mut Resolver<'_>,
    message: &ArchiveV2HotMessagePayload,
    account_objects: bool,
) -> std::result::Result<Value, String> {
    match message {
        ArchiveV2HotMessagePayload::Legacy(message) => {
            message_fields_value(
                resolver,
                message.header,
                &message.account_keys,
                &message.recent_blockhash,
                &message.instructions,
                None,
                account_objects,
                None,
            )
            .await
        }
        ArchiveV2HotMessagePayload::V0(message) => {
            message_fields_value(
                resolver,
                message.header,
                &message.account_keys,
                &message.recent_blockhash,
                &message.instructions,
                Some(&message.address_table_lookups),
                account_objects,
                None,
            )
            .await
        }
        ArchiveV2HotMessagePayload::V1(message) => {
            message_fields_value(
                resolver,
                message.header,
                &message.account_keys,
                &message.recent_blockhash,
                &message.instructions,
                None,
                account_objects,
                Some(&message.config),
            )
            .await
        }
    }
}

async fn message_fields_value(
    resolver: &mut Resolver<'_>,
    header: blockzilla_compact::CompactMessageHeader,
    account_keys: &[CompactPubkey],
    recent_blockhash: &OwnedCompactRecentBlockhash,
    instructions: &[blockzilla_archive_v2::ArchiveV2HotInstruction],
    address_table_lookups: Option<&[OwnedCompactAddressTableLookup]>,
    account_objects: bool,
    transaction_config: Option<&CompactTransactionConfig>,
) -> std::result::Result<Value, String> {
    let keys_value = if account_objects {
        let program_id_indices = message_program_id_indices(instructions);
        account_key_objects_value(
            resolver,
            header,
            account_keys,
            &program_id_indices,
            &[],
            &[],
        )
        .await?
    } else {
        compact_pubkey_array_value(resolver, account_keys).await?
    };
    let mut out = Map::new();
    out.insert("accountKeys".to_string(), keys_value);
    out.insert(
        "instructions".to_string(),
        instruction_array_value(instructions, Some(resolver))?,
    );
    out.insert(
        "recentBlockhash".to_string(),
        Value::String(resolver.resolve_recent_blockhash(recent_blockhash).await?),
    );
    out.insert(
        "header".to_string(),
        json!({
            "numRequiredSignatures": header.num_required_signatures,
            "numReadonlySignedAccounts": header.num_readonly_signed_accounts,
            "numReadonlyUnsignedAccounts": header.num_readonly_unsigned_accounts,
        }),
    );
    if let Some(lookups) = address_table_lookups {
        let mut items = Vec::with_capacity(lookups.len());
        for lookup in lookups {
            items.push(json!({
                "accountKey": resolver.resolve_pubkey(lookup.account_key).await?,
                "writableIndexes": lookup.writable_indexes,
                "readonlyIndexes": lookup.readonly_indexes,
            }));
        }
        out.insert("addressTableLookups".to_string(), Value::Array(items));
    }
    if let Some(config) = transaction_config {
        out.insert("transactionConfig".into(), transaction_config_value(config));
    }
    Ok(Value::Object(out))
}

async fn compact_pubkey_array_value(
    resolver: &mut Resolver<'_>,
    keys: &[CompactPubkey],
) -> std::result::Result<Value, String> {
    let mut out = Vec::with_capacity(keys.len());
    for key in keys {
        out.push(Value::String(resolver.resolve_pubkey(*key).await?));
    }
    Ok(Value::Array(out))
}

async fn account_key_objects_value(
    resolver: &mut Resolver<'_>,
    header: blockzilla_compact::CompactMessageHeader,
    keys: &[CompactPubkey],
    program_id_indices: &[u8],
    loaded_writable_addresses: &[CompactPubkey],
    loaded_readonly_addresses: &[CompactPubkey],
) -> std::result::Result<Value, String> {
    let required_signatures = header.num_required_signatures as usize;
    let readonly_signed = header.num_readonly_signed_accounts as usize;
    let readonly_unsigned = header.num_readonly_unsigned_accounts as usize;
    let signed_writable = required_signatures.saturating_sub(readonly_signed);
    let unsigned_writable_end = keys.len().saturating_sub(readonly_unsigned);
    let mut out = Vec::new();
    for (index, key) in keys.iter().enumerate() {
        let signer = index < required_signatures;
        let header_writable = if signer {
            index < signed_writable
        } else {
            index < unsigned_writable_end
        };
        let writable = header_writable
            && u8::try_from(index)
                .ok()
                .is_none_or(|index| !program_id_indices.contains(&index));
        let pubkey = resolver.resolve_pubkey(*key).await?;
        let writable = writable && !is_reserved_readonly_account(&pubkey);
        out.push(json!({
            "pubkey": pubkey,
            "signer": signer,
            "source": "transaction",
            "writable": writable,
        }));
    }
    for key in loaded_writable_addresses {
        out.push(json!({
            "pubkey": resolver.resolve_pubkey(*key).await?,
            "signer": false,
            "source": "lookupTable",
            "writable": true,
        }));
    }
    for key in loaded_readonly_addresses {
        out.push(json!({
            "pubkey": resolver.resolve_pubkey(*key).await?,
            "signer": false,
            "source": "lookupTable",
            "writable": false,
        }));
    }
    Ok(Value::Array(out))
}

fn message_program_id_indices(
    instructions: &[blockzilla_archive_v2::ArchiveV2HotInstruction],
) -> Vec<u8> {
    let mut indices = instructions
        .iter()
        .map(|instruction| instruction.program_id_index)
        .collect::<Vec<_>>();
    indices.sort_unstable();
    indices.dedup();
    indices
}

fn is_reserved_readonly_account(pubkey: &str) -> bool {
    matches!(
        pubkey,
        "11111111111111111111111111111111"
            | "SysvarC1ock11111111111111111111111111111111"
            | "SysvarEpochSchedu1e111111111111111111111111"
            | "SysvarFees111111111111111111111111111111111"
            | "SysvarRecentB1ockHashes11111111111111111111"
            | "SysvarRent111111111111111111111111111111111"
            | "SysvarRewards111111111111111111111111111111"
            | "SysvarS1otHashes111111111111111111111111111"
            | "SysvarS1otHistory11111111111111111111111111"
            | "SysvarStakeHistory1111111111111111111111111"
            | "Sysvar1nstructions1111111111111111111111111"
            | "SysvarLastRestartS1ot1111111111111111111111"
    )
}

fn instruction_array_value(
    instructions: &[blockzilla_archive_v2::ArchiveV2HotInstruction],
    resolver: Option<&Resolver<'_>>,
) -> std::result::Result<Value, String> {
    Ok(Value::Array(
        instructions
            .iter()
            .map(|instruction| {
                Ok(json!({
                    "programIdIndex": instruction.program_id_index,
                    "accounts": instruction.accounts,
                    "data": instruction_data_base58(&instruction.data, resolver)?,
                    "stackHeight": 1,
                }))
            })
            .collect::<std::result::Result<Vec<_>, String>>()?,
    ))
}

fn instruction_data_base58(
    data: &ArchiveV2HotInstructionData,
    resolver: Option<&Resolver<'_>>,
) -> std::result::Result<String, String> {
    match data {
        ArchiveV2HotInstructionData::Raw(bytes)
        | ArchiveV2HotInstructionData::UnknownSystem(bytes)
        | ArchiveV2HotInstructionData::UnknownVote(bytes) => Ok(base58_bytes(bytes)),
        ArchiveV2HotInstructionData::ComputeBudget(value) => {
            let mut out = Vec::new();
            match value {
                blockzilla_archive_v2::ArchiveV2ComputeBudgetInstructionData::Unused => out.push(0),
                blockzilla_archive_v2::ArchiveV2ComputeBudgetInstructionData::RequestHeapFrame(bytes) => {
                    out.push(1);
                    out.extend_from_slice(&bytes.to_le_bytes());
                }
                blockzilla_archive_v2::ArchiveV2ComputeBudgetInstructionData::SetComputeUnitLimit(units) => {
                    out.push(2);
                    out.extend_from_slice(&units.to_le_bytes());
                }
                blockzilla_archive_v2::ArchiveV2ComputeBudgetInstructionData::SetComputeUnitPrice(price) => {
                    out.push(3);
                    out.extend_from_slice(&price.to_le_bytes());
                }
                blockzilla_archive_v2::ArchiveV2ComputeBudgetInstructionData::SetLoadedAccountsDataSizeLimit(bytes) => {
                    out.push(4);
                    out.extend_from_slice(&bytes.to_le_bytes());
                }
            }
            Ok(base58_bytes(&out))
        }
        ArchiveV2HotInstructionData::System(value) => {
            Ok(base58_bytes(&system_instruction_bytes(value)))
        }
        ArchiveV2HotInstructionData::VoteCompactUpdateVoteState(update) => {
            let resolver = resolver.ok_or_else(|| {
                "compact vote instruction data requires block access vote hashes".to_string()
            })?;
            Ok(base58_bytes(&vote_update_instruction_bytes(
                12, update, resolver,
            )?))
        }
        ArchiveV2HotInstructionData::VoteCompactUpdateVoteStateSwitch {
            update,
            switch_proof_hash,
        } => {
            let resolver = resolver.ok_or_else(|| {
                "compact vote instruction data requires block access vote hashes".to_string()
            })?;
            let mut out = vote_update_instruction_bytes(13, update, resolver)?;
            out.extend_from_slice(
                &resolver.resolve_vote_hash_ref(*switch_proof_hash, VoteHashKind::Aux)?,
            );
            Ok(base58_bytes(&out))
        }
        ArchiveV2HotInstructionData::VoteTowerSync(tower) => {
            let resolver = resolver.ok_or_else(|| {
                "compact vote instruction data requires block access vote hashes".to_string()
            })?;
            Ok(base58_bytes(&vote_tower_sync_instruction_bytes(
                14, tower, resolver,
            )?))
        }
        ArchiveV2HotInstructionData::VoteTowerSyncSwitch {
            tower,
            switch_proof_hash,
        } => {
            let resolver = resolver.ok_or_else(|| {
                "compact vote instruction data requires block access vote hashes".to_string()
            })?;
            let mut out = vote_tower_sync_instruction_bytes(15, tower, resolver)?;
            out.extend_from_slice(
                &resolver.resolve_vote_hash_ref(*switch_proof_hash, VoteHashKind::Aux)?,
            );
            Ok(base58_bytes(&out))
        }
    }
}

#[derive(Clone, Copy)]
enum VoteHashKind {
    Bank,
    BlockId,
    Aux,
}

fn vote_update_instruction_bytes(
    variant: u32,
    update: &ArchiveV2VoteStateUpdate,
    resolver: &Resolver<'_>,
) -> std::result::Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(128);
    push_u32_le(&mut out, variant);
    push_u64_le(&mut out, update.root.unwrap_or(u64::MAX));
    push_short_vec_len(&mut out, update.lockout_offsets.len())?;
    for lockout in &update.lockout_offsets {
        push_var_u64(&mut out, lockout.offset);
        out.push(lockout.confirmation_count);
    }
    out.extend_from_slice(&resolver.resolve_vote_hash_ref(update.hash, VoteHashKind::Bank)?);
    push_option_i64(&mut out, update.timestamp);
    Ok(out)
}

fn vote_tower_sync_instruction_bytes(
    variant: u32,
    tower: &ArchiveV2VoteTowerSync,
    resolver: &Resolver<'_>,
) -> std::result::Result<Vec<u8>, String> {
    let mut out = vote_update_instruction_bytes(variant, &tower.update, resolver)?;
    out.extend_from_slice(
        &resolver.resolve_vote_hash_ref(tower.block_id_hash, VoteHashKind::BlockId)?,
    );
    Ok(out)
}

fn push_short_vec_len(out: &mut Vec<u8>, mut len: usize) -> std::result::Result<(), String> {
    if len > u16::MAX as usize {
        return Err(format!("vote short_vec length {len} exceeds u16::MAX"));
    }
    loop {
        let mut byte = (len & 0x7f) as u8;
        len >>= 7;
        if len != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if len == 0 {
            return Ok(());
        }
    }
}

fn push_var_u64(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            return;
        }
    }
}

fn push_option_i64(out: &mut Vec<u8>, value: Option<i64>) {
    match value {
        Some(value) => {
            out.push(1);
            out.extend_from_slice(&value.to_le_bytes());
        }
        None => out.push(0),
    }
}

fn system_instruction_bytes(
    data: &blockzilla_archive_v2::ArchiveV2SystemInstructionData,
) -> Vec<u8> {
    use blockzilla_archive_v2::ArchiveV2SystemInstructionData as SystemIx;

    let mut out = Vec::with_capacity(96);
    match data {
        SystemIx::CreateAccount {
            lamports,
            space,
            owner,
        } => {
            push_u32_le(&mut out, 0);
            push_u64_le(&mut out, *lamports);
            push_u64_le(&mut out, *space);
            out.extend_from_slice(owner);
        }
        SystemIx::Assign { owner } => {
            push_u32_le(&mut out, 1);
            out.extend_from_slice(owner);
        }
        SystemIx::Transfer { lamports } => {
            push_u32_le(&mut out, 2);
            push_u64_le(&mut out, *lamports);
        }
        SystemIx::CreateAccountWithSeed {
            base,
            seed,
            lamports,
            space,
            owner,
        } => {
            push_u32_le(&mut out, 3);
            out.extend_from_slice(base);
            push_system_seed(&mut out, seed);
            push_u64_le(&mut out, *lamports);
            push_u64_le(&mut out, *space);
            out.extend_from_slice(owner);
        }
        SystemIx::AdvanceNonceAccount => {
            push_u32_le(&mut out, 4);
        }
        SystemIx::WithdrawNonceAccount { lamports } => {
            push_u32_le(&mut out, 5);
            push_u64_le(&mut out, *lamports);
        }
        SystemIx::InitializeNonceAccount { authority } => {
            push_u32_le(&mut out, 6);
            out.extend_from_slice(authority);
        }
        SystemIx::AuthorizeNonceAccount { authority } => {
            push_u32_le(&mut out, 7);
            out.extend_from_slice(authority);
        }
        SystemIx::Allocate { space } => {
            push_u32_le(&mut out, 8);
            push_u64_le(&mut out, *space);
        }
        SystemIx::AllocateWithSeed {
            base,
            seed,
            space,
            owner,
        } => {
            push_u32_le(&mut out, 9);
            out.extend_from_slice(base);
            push_system_seed(&mut out, seed);
            push_u64_le(&mut out, *space);
            out.extend_from_slice(owner);
        }
        SystemIx::AssignWithSeed { base, seed, owner } => {
            push_u32_le(&mut out, 10);
            out.extend_from_slice(base);
            push_system_seed(&mut out, seed);
            out.extend_from_slice(owner);
        }
        SystemIx::TransferWithSeed {
            lamports,
            from_seed,
            from_owner,
        } => {
            push_u32_le(&mut out, 11);
            push_u64_le(&mut out, *lamports);
            push_system_seed(&mut out, from_seed);
            out.extend_from_slice(from_owner);
        }
        SystemIx::UpgradeNonceAccount => {
            push_u32_le(&mut out, 12);
        }
        SystemIx::CreateAccountAllowPrefund {
            lamports,
            space,
            owner,
        } => {
            push_u32_le(&mut out, 13);
            push_u64_le(&mut out, *lamports);
            push_u64_le(&mut out, *space);
            out.extend_from_slice(owner);
        }
    }
    out
}

fn push_u32_le(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u64_le(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_system_seed(out: &mut Vec<u8>, seed: &str) {
    push_u64_le(out, seed.len() as u64);
    out.extend_from_slice(seed.as_bytes());
}

async fn metadata_value(
    resolver: &mut Resolver<'_>,
    meta: Option<&CompactMetaV1>,
) -> std::result::Result<Value, String> {
    let Some(meta) = meta else {
        return Ok(Value::Null);
    };
    let err = transaction_error_value(meta.err.as_ref())?;
    let status = if err.is_null() {
        json!({ "Ok": null })
    } else {
        json!({ "Err": err.clone() })
    };
    let mut out = Map::new();
    out.insert("err".to_string(), err);
    out.insert("status".to_string(), status);
    out.insert("fee".to_string(), Value::from(meta.fee));
    out.insert("preBalances".to_string(), json!(meta.pre_balances));
    out.insert("postBalances".to_string(), json!(meta.post_balances));
    out.insert(
        "preTokenBalances".to_string(),
        token_balances_value(resolver, &meta.pre_token_balances, false).await?,
    );
    out.insert(
        "postTokenBalances".to_string(),
        token_balances_value(resolver, &meta.post_token_balances, false).await?,
    );
    out.insert(
        "logMessages".to_string(),
        log_messages_value(resolver, meta.logs.as_ref()).await?,
    );
    out.insert(
        "innerInstructions".to_string(),
        inner_instructions_value(meta.inner_instructions.as_deref()),
    );
    out.insert(
        "loadedAddresses".to_string(),
        json!({
            "writable": compact_pubkey_array_value(resolver, &meta.loaded_writable_addresses).await?,
            "readonly": compact_pubkey_array_value(resolver, &meta.loaded_readonly_addresses).await?,
        }),
    );
    if let Some(return_data) = &meta.return_data {
        out.insert(
            "returnData".to_string(),
            return_data_value(resolver, return_data).await?,
        );
    }
    out.insert(
        "rewards".to_string(),
        compact_rewards_value(resolver, &meta.rewards).await?,
    );
    if let Some(value) = meta.compute_units_consumed {
        out.insert("computeUnitsConsumed".to_string(), Value::from(value));
    }
    if let Some(value) = meta.cost_units {
        out.insert("costUnits".to_string(), Value::from(value));
    }
    Ok(Value::Object(out))
}

async fn return_data_value(
    resolver: &mut Resolver<'_>,
    return_data: &CompactReturnData,
) -> std::result::Result<Value, String> {
    Ok(json!({
        "programId": resolver.resolve_pubkey(return_data.program_id).await?,
        "data": [BASE64.encode(&return_data.data), "base64".to_string()],
    }))
}

async fn account_metadata_value(
    resolver: &mut Resolver<'_>,
    meta: Option<&CompactMetaV1>,
    include_rewards: bool,
) -> std::result::Result<Value, String> {
    let Some(meta) = meta else {
        return Ok(Value::Null);
    };
    let err = transaction_error_value(meta.err.as_ref())?;
    let status = if err.is_null() {
        json!({ "Ok": null })
    } else {
        json!({ "Err": err.clone() })
    };
    let mut out = Map::new();
    out.insert("err".to_string(), err);
    out.insert("status".to_string(), status);
    out.insert("fee".to_string(), Value::from(meta.fee));
    out.insert("preBalances".to_string(), json!(meta.pre_balances));
    out.insert("postBalances".to_string(), json!(meta.post_balances));
    out.insert(
        "preTokenBalances".to_string(),
        token_balances_value(resolver, &meta.pre_token_balances, false).await?,
    );
    out.insert(
        "postTokenBalances".to_string(),
        token_balances_value(resolver, &meta.post_token_balances, false).await?,
    );
    if include_rewards {
        out.insert(
            "rewards".to_string(),
            compact_rewards_value(resolver, &meta.rewards).await?,
        );
    }
    Ok(Value::Object(out))
}

fn account_metadata_lite_value(
    meta: Option<&AccountMetaLite>,
    include_rewards: bool,
) -> std::result::Result<Value, String> {
    let Some(meta) = meta else {
        return Ok(Value::Null);
    };
    let err = transaction_error_value(meta.err.as_ref())?;
    let status = if err.is_null() {
        json!({ "Ok": null })
    } else {
        json!({ "Err": err.clone() })
    };
    let mut out = json!({
        "err": err,
        "status": status,
        "fee": meta.fee,
        "preBalances": meta.pre_balances,
        "postBalances": meta.post_balances,
        "preTokenBalances": token_balances_lite_value(meta.pre_token_balance_count),
        "postTokenBalances": token_balances_lite_value(meta.post_token_balance_count),
    });
    if include_rewards && let Value::Object(map) = &mut out {
        map.insert("rewards".to_string(), Value::Null);
    }
    Ok(out)
}

fn token_balances_lite_value(_count: usize) -> Value {
    json!([])
}

async fn token_balances_value(
    resolver: &mut Resolver<'_>,
    balances: &[blockzilla_compact::CompactTokenBalance],
    ui_amount_null: bool,
) -> std::result::Result<Value, String> {
    let mut out = Vec::with_capacity(balances.len());
    for balance in balances {
        out.push(token_balance_value(resolver, balance, ui_amount_null).await?);
    }
    Ok(Value::Array(out))
}

async fn token_balance_value(
    resolver: &mut Resolver<'_>,
    balance: &blockzilla_compact::CompactTokenBalance,
    ui_amount_null: bool,
) -> std::result::Result<Value, String> {
    let mut out = Map::new();
    out.insert(
        "accountIndex".to_string(),
        Value::from(u64::from(balance.account_index)),
    );
    if let Some(mint) = balance.mint {
        out.insert(
            "mint".to_string(),
            Value::String(resolver.resolve_pubkey(mint).await?),
        );
    }
    if let Some(owner) = balance.owner {
        out.insert(
            "owner".to_string(),
            Value::String(resolver.resolve_pubkey(owner).await?),
        );
    }
    if let Some(program_id) = balance.program_id {
        out.insert(
            "programId".to_string(),
            Value::String(resolver.resolve_pubkey(program_id).await?),
        );
    }
    out.insert(
        "uiTokenAmount".to_string(),
        ui_token_amount_value(balance.amount, balance.decimals, ui_amount_null),
    );
    Ok(Value::Object(out))
}

fn ui_token_amount_value(amount: u64, decimals: u8, _ui_amount_null: bool) -> Value {
    json!({
        "amount": amount.to_string(),
        "decimals": decimals,
        "uiAmount": if amount == 0 { Value::Null } else { json!(ui_amount_number(amount, decimals)) },
        "uiAmountString": ui_amount_string(amount, decimals),
    })
}

fn ui_amount_number(amount: u64, decimals: u8) -> f64 {
    (amount as f64) / 10f64.powi(i32::from(decimals))
}

fn ui_amount_string(amount: u64, decimals: u8) -> String {
    if decimals == 0 {
        return amount.to_string();
    }
    let decimals = decimals as usize;
    let mut digits = amount.to_string();
    if digits.len() <= decimals {
        let zeros = decimals + 1 - digits.len();
        let mut padded = String::with_capacity(decimals + 1);
        padded.extend(std::iter::repeat_n('0', zeros));
        padded.push_str(&digits);
        digits = padded;
    }
    let split = digits.len() - decimals;
    let (whole, fraction) = digits.split_at(split);
    let fraction = fraction.trim_end_matches('0');
    if fraction.is_empty() {
        whole.to_string()
    } else {
        format!("{whole}.{fraction}")
    }
}

async fn log_messages_value(
    resolver: &mut Resolver<'_>,
    logs: Option<&CompactLogStream>,
) -> std::result::Result<Value, String> {
    let Some(logs) = logs else {
        return Ok(Value::Null);
    };
    Ok(render_logs_with_resolver(resolver, logs)
        .await
        .map(Value::from)
        .unwrap_or_else(|| Value::Array(Vec::new())))
}

fn inner_instructions_value(inner_instructions: Option<&[CompactInnerInstructions]>) -> Value {
    let Some(inner_instructions) = inner_instructions else {
        return Value::Null;
    };
    Value::Array(
        inner_instructions
            .iter()
            .map(|group| {
                json!({
                    "index": group.index,
                    "instructions": group.instructions.iter().map(inner_instruction_value).collect::<Vec<_>>(),
                })
            })
            .collect(),
    )
}

fn inner_instruction_value(instruction: &blockzilla_compact::CompactInnerInstruction) -> Value {
    json!({
        "programIdIndex": instruction.program_id_index,
        "accounts": instruction.accounts,
        "data": base58_bytes(&instruction.data),
        "stackHeight": instruction.stack_height,
    })
}

async fn compact_rewards_value(
    resolver: &mut Resolver<'_>,
    rewards: &[CompactReward],
) -> std::result::Result<Value, String> {
    if rewards.is_empty() {
        return Ok(Value::Array(Vec::new()));
    }
    let mut out = Vec::with_capacity(rewards.len());
    for reward in rewards {
        out.push(compact_reward_value(resolver, reward).await?);
    }
    Ok(Value::Array(out))
}

async fn compact_reward_value(
    resolver: &mut Resolver<'_>,
    reward: &CompactReward,
) -> std::result::Result<Value, String> {
    Ok(json!({
        "pubkey": resolver.resolve_pubkey(reward.pubkey).await?,
        "lamports": reward.lamports,
        "postBalance": reward.post_balance,
        "rewardType": match reward.reward_type {
            1 => Value::String("Fee".to_string()),
            2 => Value::String("Rent".to_string()),
            3 => Value::String("Staking".to_string()),
            4 => Value::String("Voting".to_string()),
            _ => Value::Null,
        },
        "commission": reward.commission,
    }))
}

async fn rewards_value(
    resolver: &mut Resolver<'_>,
    rewards: Option<&blockzilla_archive_v2::ArchiveV2HotRewards>,
) -> std::result::Result<Value, String> {
    let Some(rewards) = rewards else {
        return Ok(Value::Null);
    };
    let mut out = Vec::with_capacity(rewards.decoded.len());
    for reward in &rewards.decoded {
        out.push(json!({
            "pubkey": resolver.resolve_pubkey(reward.pubkey).await?,
            "lamports": reward.lamports,
            "postBalance": reward.post_balance,
            "rewardType": match reward.reward_type {
                1 => Value::String("Fee".to_string()),
                2 => Value::String("Rent".to_string()),
                3 => Value::String("Staking".to_string()),
                4 => Value::String("Voting".to_string()),
                _ => Value::Null,
            },
            "commission": reward.commission,
        }));
    }
    Ok(Value::Array(out))
}

fn message_version_value(message: &ArchiveV2HotMessagePayload) -> Value {
    match message {
        ArchiveV2HotMessagePayload::Legacy(_) => Value::String("legacy".to_string()),
        ArchiveV2HotMessagePayload::V0(_) => Value::from(0),
        ArchiveV2HotMessagePayload::V1(_) => Value::from(1),
    }
}

struct Resolver<'a> {
    source: &'a WorkerSource,
    access: Option<&'a ArchiveV2BlockAccessBlob>,
}

impl<'a> Resolver<'a> {
    fn new(source: &'a WorkerSource, access: Option<&'a ArchiveV2BlockAccessBlob>) -> Self {
        Self { source, access }
    }

    async fn resolve_pubkey(&mut self, key: CompactPubkey) -> std::result::Result<String, String> {
        let bytes = self.resolve_pubkey_bytes(key).await?;
        Ok(base58_32(&bytes))
    }

    async fn resolve_pubkey_bytes(
        &mut self,
        key: CompactPubkey,
    ) -> std::result::Result<[u8; 32], String> {
        let bytes = match key {
            CompactPubkey::Raw(bytes) => bytes,
            CompactPubkey::Id(id) => {
                if let Some(bytes) = self.access_pubkey(id) {
                    return Ok(bytes);
                }
                return Err(format!(
                    "block access is missing pubkey id {id}; registry fallback is disabled"
                ));
            }
        };
        Ok(bytes)
    }

    fn access_pubkey(&self, id: u32) -> Option<[u8; 32]> {
        let pubkeys = &self.access?.pubkeys;
        if let Some(index) = pubkeys.binary_search_by_key(&id, |entry| entry.id).ok() {
            return Some(pubkeys[index].pubkey);
        }
        pubkeys
            .iter()
            .find(|entry| entry.id == id)
            .map(|entry| entry.pubkey)
    }

    async fn resolve_recent_blockhash(
        &mut self,
        value: &OwnedCompactRecentBlockhash,
    ) -> std::result::Result<String, String> {
        let bytes = self.resolve_recent_blockhash_bytes(value).await?;
        Ok(base58_32(&bytes))
    }

    async fn resolve_recent_blockhash_bytes(
        &mut self,
        value: &OwnedCompactRecentBlockhash,
    ) -> std::result::Result<[u8; 32], String> {
        match value {
            OwnedCompactRecentBlockhash::Id(id) => self.resolve_blockhash_id_bytes(*id).await,
            OwnedCompactRecentBlockhash::Nonce(bytes) => Ok(*bytes),
        }
    }

    async fn resolve_blockhash_id(&mut self, id: i32) -> std::result::Result<String, String> {
        let bytes = self.resolve_blockhash_id_bytes(id).await?;
        Ok(base58_32(&bytes))
    }

    async fn resolve_blockhash_id_bytes(
        &mut self,
        id: i32,
    ) -> std::result::Result<[u8; 32], String> {
        if let Some(bytes) = self.access_blockhash(id) {
            return Ok(bytes);
        }
        Err(format!(
            "block access is missing blockhash id {id}; registry fallback is disabled"
        ))
    }

    fn access_blockhash(&self, id: i32) -> Option<[u8; 32]> {
        let blockhashes = &self.access?.blockhashes;
        blockhashes
            .binary_search_by_key(&id, |entry| entry.id)
            .ok()
            .map(|index| blockhashes[index].blockhash)
    }

    fn resolve_vote_hash_ref(
        &self,
        value: ArchiveV2VoteHashRef,
        kind: VoteHashKind,
    ) -> std::result::Result<[u8; 32], String> {
        match value {
            ArchiveV2VoteHashRef::Zero => Ok([0u8; 32]),
            ArchiveV2VoteHashRef::Raw(hash) => Ok(hash),
            ArchiveV2VoteHashRef::Block(block_id) => {
                let Some(access) = self.access else {
                    return Err(format!(
                        "block access is missing vote hash block id {block_id}; fallback is disabled"
                    ));
                };
                let Some(entry) = access
                    .vote_hashes
                    .iter()
                    .find(|entry| entry.block_id == block_id)
                else {
                    return Err(format!(
                        "block access is missing vote hash block id {block_id}; fallback is disabled"
                    ));
                };
                match kind {
                    VoteHashKind::Bank => entry.bank_hash.ok_or_else(|| {
                        format!("block access vote hash block id {block_id} is missing bank hash")
                    }),
                    VoteHashKind::BlockId => entry.block_id_hash.ok_or_else(|| {
                        format!(
                            "block access vote hash block id {block_id} is missing block-id hash"
                        )
                    }),
                    VoteHashKind::Aux => Err(format!(
                        "aux vote hash unexpectedly references block id {block_id}"
                    )),
                }
            }
        }
    }

    async fn read_block_signatures(
        &self,
        row: &ArchiveV2HotBlockIndexRow,
    ) -> std::result::Result<Vec<String>, String> {
        if let Some(access) = self.access {
            return Ok(access
                .signatures
                .chunks_exact(SIGNATURE_BYTES as usize)
                .map(|signature| base58_bytes(signature))
                .collect());
        }
        let _ = row;
        Err("block access is missing signatures; signatures file fallback is disabled".to_string())
    }
}

fn region_slice<'a>(
    bytes: &'a [u8],
    offset: u32,
    len: u32,
    label: &str,
    tx_index: u32,
) -> std::result::Result<&'a [u8], String> {
    let start = offset as usize;
    let end = start
        .checked_add(len as usize)
        .ok_or_else(|| format!("{label} region overflow for tx_index {tx_index}"))?;
    bytes.get(start..end).ok_or_else(|| {
        format!(
            "{label} region out of bounds for tx_index {tx_index}: offset={offset} len={len} bytes={}",
            bytes.len()
        )
    })
}

fn epoch_for_slot(slot: u64) -> u64 {
    slot / SLOTS_PER_EPOCH
}

fn epoch_file(prefix: &str, epoch: u64, file: &str) -> String {
    if prefix.is_empty() {
        format!("epoch-{epoch}/{file}")
    } else {
        format!("{prefix}/epoch-{epoch}/{file}")
    }
}

fn rpc_block_time(value: Option<i64>) -> Option<i64> {
    value.filter(|value| *value != 0)
}

#[derive(Clone)]
struct WorkerSource {
    archive_prefix: String,
    backend: ArchiveBackend,
    profile: Option<ProfileHandle>,
    backend_read: BackendReadTracker,
    storage_metrics: StorageMetrics,
    stored_compact: bool,
    use_dense_slot_index: bool,
    cache: Option<ArchiveCache>,
    object_sizes: Rc<RefCell<BTreeMap<String, u64>>>,
    signature_locator: Option<transaction::LocatorConfig>,
    message_schema_overrides: BTreeMap<u64, MessageSchema>,
    metadata_schema_override: Option<MetadataSchema>,
    cache_write_bytes: Rc<Cell<usize>>,
    resolution: Option<resolution::Config>,
    native_reader: Option<native_reader::Config>,
    slot_bundle: Option<bundle_object::Config>,
    foundation_lookup: Option<foundation_first::Config>,
    // Request-local transport state. This cell is never stored in a global cache.
    foundation_prepared: Rc<RefCell<Option<foundation_first::Outcome>>>,
}

#[derive(Clone)]
enum ArchiveBackend {
    R2 { bucket: Bucket, binding: String },
    S3(S3Source),
}

#[derive(Clone)]
struct S3Source {
    endpoint: String,
    host: String,
    bucket: String,
    region: String,
    access_key: String,
    secret_key: String,
}

#[derive(Clone, Copy)]
enum StorageBackendKind {
    R2,
    S3,
}

impl WorkerSource {
    fn from_env(
        env: &worker::Env,
        profile: Option<ProfileHandle>,
    ) -> std::result::Result<Self, String> {
        let source = optional_var(env, "BZ_ARCHIVE_SOURCE").unwrap_or_else(|| "auto".to_string());
        let archive_prefix = optional_var(env, "BZ_ARCHIVE_PREFIX")
            .unwrap_or_else(|| "compact-v2/blockzilla-20261004".to_string())
            .trim_matches('/')
            .to_string();
        let generation = required_var(env, "BZ_ARCHIVE_GENERATION")?;
        if generation.is_empty() || generation.len() > 128 {
            return Err("BZ_ARCHIVE_GENERATION must contain 1 to 128 bytes".into());
        }
        let stored_compact = match optional_var(env, "BZ_ARCHIVE_LAYOUT")
            .as_deref()
            .unwrap_or("stored")
        {
            "stored" => true,
            "legacy-access" => false,
            _ => return Err("BZ_ARCHIVE_LAYOUT must be stored or legacy-access".into()),
        };
        let use_dense_slot_index = match optional_var(env, "BZ_SLOT_INDEX")
            .as_deref()
            .unwrap_or("sparse")
        {
            "dense" => true,
            "sparse" => false,
            _ => return Err("BZ_SLOT_INDEX must be sparse or dense".into()),
        };
        let backend = match source.as_str() {
            "auto" => {
                let binding = r2_binding_name(env);
                match env.bucket(&binding) {
                    Ok(bucket) => ArchiveBackend::R2 { bucket, binding },
                    Err(_) => ArchiveBackend::S3(S3Source::from_env(env)?),
                }
            }
            "r2" | "cloudflare" | "cloudflare-r2" => {
                let binding = r2_binding_name(env);
                let bucket = env
                    .bucket(&binding)
                    .map_err(|err| format!("missing R2 bucket binding {binding}: {err}"))?;
                ArchiveBackend::R2 { bucket, binding }
            }
            "s3" | "backblaze" | "b2" => ArchiveBackend::S3(S3Source::from_env(env)?),
            _ => {
                return Err(
                    "BZ_ARCHIVE_SOURCE must be auto, r2, cloudflare-r2, s3, backblaze, or b2"
                        .to_string(),
                );
            }
        };
        let native_reader = native_reader::Config::from_env(env, &archive_prefix)?;
        let foundation_lookup = foundation_first::Config::from_env(env, &archive_prefix)?;
        Ok(Self {
            archive_prefix,
            backend,
            profile,
            backend_read: BackendReadTracker::default(),
            storage_metrics: StorageMetrics::default(),
            cache_write_bytes: Rc::new(Cell::new(0)),
            message_schema_overrides: crate::archive_schema::message_schema_overrides(
                optional_var(env, "BZ_MESSAGE_SCHEMA_OVERRIDES").as_deref(),
            )?,
            metadata_schema_override: crate::archive_schema::metadata_schema_override(
                optional_var(env, "BZ_METADATA_SCHEMA").as_deref(),
            )?,
            stored_compact,
            use_dense_slot_index,
            cache: None,
            object_sizes: Rc::new(RefCell::new(BTreeMap::new())),
            signature_locator: transaction::LocatorConfig::from_env(env)?,
            resolution: resolution::Config::from_env(env)?,
            native_reader,
            slot_bundle: bundle_object::Config::from_env(env)?,
            foundation_lookup,
            foundation_prepared: Rc::new(RefCell::new(None)),
        })
    }

    fn billable_backend_reads(&self) -> u8 {
        self.backend_read.billable_reads()
    }

    fn record_elapsed(
        &self,
        name: &str,
        started_ms: f64,
        bytes: u64,
        detail: impl Into<String>,
        status: Option<u16>,
    ) {
        if let Some(profile) = &self.profile {
            profile.record_elapsed(name, started_ms, bytes, detail, status);
        }
    }

    async fn get_range(
        &self,
        path: &str,
        offset: u64,
        len: usize,
    ) -> std::result::Result<Vec<u8>, String> {
        if len == 0 {
            return Ok(Vec::new());
        }
        if len > MAX_ARCHIVE_RANGE_BYTES {
            return Err(format!(
                "archive range exceeds the {MAX_ARCHIVE_RANGE_BYTES}-byte Worker limit"
            ));
        }
        ensure_js_safe_range(offset, len)?;
        let bytes = self.get_range_inner(path, offset, len).await?;
        if bytes.len() != len {
            return Err(format!(
                "archive GET {path} returned {} bytes for {}, expected {len}",
                bytes.len(),
                range_fetch_detail(path, offset, len)
            ));
        }
        Ok(bytes)
    }

    fn range_cache_key(&self, path: &str, offset: u64, len: usize) -> Option<String> {
        let cache = self.cache.as_ref()?;
        Some(format!(
            "{}/__blockzilla-archive/v1/{}/{}",
            cache.origin,
            cache.generation,
            api_key_digest(&format!("range\0{path}\0{offset}\0{len}"))
        ))
    }

    async fn cached_bytes(&self, key: &str, expected: usize) -> Option<Vec<u8>> {
        if let Some(bytes) = ARCHIVE_BYTES.with(|cache| cache.borrow_mut().get(key)) {
            if bytes.len() == expected {
                self.storage_metrics.memory_hit();
                return Some(bytes);
            }
        }
        let started = now_ms();
        if let Ok(Some(mut response)) = Cache::default().get(key.to_string(), false).await {
            // Cache entries are written only by this Worker under a private
            // content namespace. Check the size before buffering a cache body.
            let length = response
                .headers()
                .get("Content-Length")
                .ok()
                .flatten()
                .and_then(|value| value.parse::<usize>().ok());
            if response.status_code() == 200 && length == Some(expected) {
                if let Ok(bytes) = response.bytes().await {
                    if bytes.len() == expected {
                        if expected <= 64 * 1024 {
                            ARCHIVE_BYTES.with(|cache| {
                                cache.borrow_mut().insert(key.to_string(), bytes.clone())
                            });
                        }
                        self.storage_metrics.edge_hit();
                        self.record_elapsed(
                            "archive_cache_hit",
                            started,
                            bytes.len() as u64,
                            "range",
                            None,
                        );
                        return Some(bytes);
                    }
                }
            }
        }
        None
    }

    fn cache_bytes(&self, key: String, bytes: &[u8]) {
        let Some(cache) = &self.cache else {
            return;
        };
        if bytes.len() <= 64 * 1024 {
            ARCHIVE_BYTES.with(|cache| cache.borrow_mut().insert(key.clone(), bytes.to_vec()));
        }
        // Background cache writes retain their bodies until completion. Bound
        // the total queued payload independently of network-read admission.
        let queued = self.cache_write_bytes.get().saturating_add(bytes.len());
        if queued > 8 * 1024 * 1024 {
            return;
        }
        self.cache_write_bytes.set(queued);
        let Ok(mut response) = Response::from_bytes(bytes.to_vec()) else {
            return;
        };
        if response
            .headers_mut()
            .set("Cache-Control", BLOCK_CACHE_CONTROL)
            .is_err()
            || response
                .headers_mut()
                .set("Content-Length", &bytes.len().to_string())
                .is_err()
        {
            return;
        }
        // Complete cache writes after response creation, outside its latency.
        cache.context.wait_until(async move {
            if let Err(error) = Cache::default().put(key, response).await {
                console_error!("{}", json!({"event":"archive_cache_error", "operation":"put", "error":error.to_string()}));
            }
        });
    }

    async fn get_cached_range(
        &self,
        path: &str,
        offset: u64,
        len: usize,
    ) -> std::result::Result<Vec<u8>, String> {
        if len == 0 {
            return Ok(Vec::new());
        }
        let key = (len <= MAX_CACHED_RANGE_BYTES)
            .then(|| self.range_cache_key(path, offset, len))
            .flatten();
        if let Some(key) = &key {
            if let Some(bytes) = self.cached_bytes(key, len).await {
                return Ok(bytes);
            }
        }
        let bytes = self.get_range(path, offset, len).await?;
        if let Some(key) = key {
            self.cache_bytes(key, &bytes);
        }
        Ok(bytes)
    }

    async fn object_size(&self, path: &str) -> std::result::Result<Option<u64>, String> {
        if let Some(size) = self.object_sizes.borrow().get(path).copied() {
            return Ok(Some(size));
        }
        let key = self.cache.as_ref().map(|cache| {
            format!(
                "{}/__blockzilla-archive/v1/{}/{}",
                cache.origin,
                cache.generation,
                api_key_digest(&format!("size\0{path}"))
            )
        });
        if let Some(key) = &key {
            if let Some(bytes) = self.cached_bytes(key, 8).await {
                let size = u64::from_le_bytes(bytes.try_into().expect("checked cached size"));
                self.object_sizes
                    .borrow_mut()
                    .insert(path.to_string(), size);
                return Ok(Some(size));
            }
        }
        self.backend_read.mark();
        let size = match &self.backend {
            ArchiveBackend::R2 { bucket, .. } => {
                self.storage_metrics.attempt_head(StorageBackend::R2);
                let object = bucket
                    .head(path.trim_start_matches('/'))
                    .await
                    .map_err(|err| format!("R2 HEAD {path}: {err}"))?;
                self.storage_metrics
                    .complete_head(StorageBackend::R2, object.is_some());
                object.map(|object| object.size())
            }
            ArchiveBackend::S3(source) => {
                let (url, headers) = source.signed_request("HEAD", path, None)?;
                let mut init = RequestInit::new();
                init.with_method(Method::Head).with_headers(headers);
                let request = Request::new_with_init(&url, &init).map_err(|err| err.to_string())?;
                self.storage_metrics.attempt_head(StorageBackend::S3);
                let response = Fetch::Request(request)
                    .send()
                    .await
                    .map_err(|err| err.to_string())?;
                self.storage_metrics
                    .complete_head(StorageBackend::S3, response.status_code() == 200);
                match response.status_code() {
                    404 => None,
                    200 => Some(
                        response
                            .headers()
                            .get("Content-Length")
                            .map_err(|err| err.to_string())?
                            .ok_or_else(|| "S3 HEAD is missing Content-Length".to_string())?
                            .parse::<u64>()
                            .map_err(|err| err.to_string())?,
                    ),
                    status => return Err(format!("S3 HEAD {path} returned HTTP {status}")),
                }
            }
        };
        if let (Some(key), Some(size)) = (key, size) {
            self.cache_bytes(key, &size.to_le_bytes());
        }
        if let Some(size) = size {
            self.object_sizes
                .borrow_mut()
                .insert(path.to_string(), size);
        }
        // Do not retain missing objects: later archive publication must become visible.
        Ok(size)
    }

    fn remember_object_size(&self, path: &str, size: u64) {
        if self
            .object_sizes
            .borrow_mut()
            .insert(path.to_string(), size)
            .is_some()
        {
            return;
        }
        if let Some(cache) = &self.cache {
            let key = format!(
                "{}/__blockzilla-archive/v1/{}/{}",
                cache.origin,
                cache.generation,
                api_key_digest(&format!("size\0{path}"))
            );
            self.cache_bytes(key, &size.to_le_bytes());
        }
    }

    async fn get_range_inner(
        &self,
        path: &str,
        offset: u64,
        len: usize,
    ) -> std::result::Result<Vec<u8>, String> {
        match &self.backend {
            ArchiveBackend::R2 { bucket, binding } => {
                self.get_r2_range(bucket, binding, path, offset, len).await
            }
            ArchiveBackend::S3(source) => self.get_s3_range(source, path, offset, len).await,
        }
    }

    async fn get_r2_range(
        &self,
        bucket: &Bucket,
        binding: &str,
        path: &str,
        offset: u64,
        len: usize,
    ) -> std::result::Result<Vec<u8>, String> {
        ensure_js_safe_range(offset, len)?;
        let started = now_ms();
        let key = path.trim_start_matches('/').to_string();
        let detail = range_fetch_detail(path, offset, len);
        let profile_name = range_fetch_profile_name(StorageBackendKind::R2, path);
        let request = bucket.get(key.clone()).range(R2Range::OffsetWithLength {
            offset,
            length: len as u64,
        });
        self.backend_read.mark();
        self.storage_metrics.attempt_get(StorageBackend::R2);
        let object = request
            .execute()
            .await
            .map_err(|err| format!("R2 GET {path} via {binding} {}: {err}", detail))?;
        let Some(object) = object else {
            self.record_elapsed(&profile_name, started, 0, detail, Some(404));
            return Err(format!(
                "R2 GET {path} via {binding} returned missing object"
            ));
        };
        self.remember_object_size(path, object.size());
        let Some(body) = object.body() else {
            self.record_elapsed(&profile_name, started, 0, detail, None);
            return Err(format!(
                "R2 GET {path} via {binding} returned metadata without a body"
            ));
        };
        let bytes = body
            .bytes()
            .await
            .map_err(|err| format!("read R2 GET {path} via {binding}: {err}"))?;
        self.storage_metrics
            .complete_get(StorageBackend::R2, bytes.len(), bytes.len() == len);
        self.record_elapsed(
            &profile_name,
            started,
            bytes.len() as u64,
            detail,
            Some(206),
        );
        Ok(bytes)
    }

    async fn get_s3_range(
        &self,
        source: &S3Source,
        path: &str,
        offset: u64,
        len: usize,
    ) -> std::result::Result<Vec<u8>, String> {
        let started = now_ms();
        let range = s3_range_header(offset, len)?;
        let detail = range_fetch_detail(path, offset, len);
        let profile_name = range_fetch_profile_name(StorageBackendKind::S3, path);
        let (url, headers) = source.signed_get(path, Some(&range))?;
        let request = request_with_headers(&url, headers)
            .map_err(|err| format!("build S3 GET {path} {range}: {err}"))?;
        self.backend_read.mark();
        self.storage_metrics.attempt_get(StorageBackend::S3);
        let mut response = Fetch::Request(request)
            .send()
            .await
            .map_err(|err| format!("S3 GET {path} {range}: {err}"))?;
        let status = response.status_code();
        if status != 206 {
            self.record_elapsed(&profile_name, started, 0, detail, Some(status));
            return Err(format!(
                "S3 GET {path} returned HTTP {status} for {range}; an exact partial response is required"
            ));
        }
        let content_range = response
            .headers()
            .get("Content-Range")
            .map_err(|err| err.to_string())?
            .ok_or_else(|| "S3 partial response is missing Content-Range".to_string())?;
        validate_content_range(&content_range, offset, len)?;
        if let Some(total) = content_range
            .rsplit_once('/')
            .and_then(|(_, total)| total.parse::<u64>().ok())
        {
            self.remember_object_size(path, total);
        }
        let content_length = response
            .headers()
            .get("Content-Length")
            .map_err(|err| err.to_string())?
            .and_then(|value| value.parse::<usize>().ok());
        if content_length != Some(len) {
            return Err("S3 partial response has an invalid Content-Length".into());
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|err| format!("read S3 GET {path} {range}: {err}"))?;
        self.storage_metrics
            .complete_get(StorageBackend::S3, bytes.len(), bytes.len() == len);
        self.record_elapsed(
            &profile_name,
            started,
            bytes.len() as u64,
            detail,
            Some(status),
        );
        Ok(bytes)
    }
}

impl S3Source {
    fn from_env(env: &worker::Env) -> std::result::Result<Self, String> {
        let endpoint = required_var(env, "BZ_S3_ENDPOINT")?
            .trim_end_matches('/')
            .to_string();
        let host = endpoint
            .strip_prefix("https://")
            .or_else(|| endpoint.strip_prefix("http://"))
            .ok_or_else(|| "BZ_S3_ENDPOINT must start with http:// or https://".to_string())?
            .split('/')
            .next()
            .unwrap_or_default()
            .to_string();
        if host.is_empty() {
            return Err("BZ_S3_ENDPOINT must include a host".to_string());
        }
        Ok(Self {
            endpoint,
            host,
            bucket: required_var(env, "BZ_S3_BUCKET")?,
            region: required_var(env, "BZ_S3_REGION")?,
            access_key: required_var(env, "BZ_S3_ACCESS_KEY_ID")?,
            secret_key: required_var(env, "BZ_S3_SECRET_ACCESS_KEY")?,
        })
    }

    fn signed_get(
        &self,
        path: &str,
        range: Option<&str>,
    ) -> std::result::Result<(String, Headers), String> {
        self.signed_request("GET", path, range)
    }

    fn signed_request(
        &self,
        method: &str,
        path: &str,
        range: Option<&str>,
    ) -> std::result::Result<(String, Headers), String> {
        let key = path.trim_start_matches('/');
        let canonical_uri = format!(
            "/{}/{}",
            uri_encode_path_segment(&self.bucket),
            uri_encode_path(key)
        );
        let url = format!("{}{}", self.endpoint, canonical_uri);
        let (date, amz_date) = amz_dates();
        let mut signed = vec![
            ("host".to_string(), self.host.clone()),
            (
                "x-amz-content-sha256".to_string(),
                "UNSIGNED-PAYLOAD".to_string(),
            ),
            ("x-amz-date".to_string(), amz_date.clone()),
        ];
        signed.sort_by(|a, b| a.0.cmp(&b.0));
        let canonical_headers = signed
            .iter()
            .map(|(name, value)| format!("{name}:{}\n", value.trim()))
            .collect::<String>();
        let signed_headers = signed
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>()
            .join(";");
        let canonical_request = format!(
            "{method}\n{canonical_uri}\n\n{canonical_headers}\n{signed_headers}\nUNSIGNED-PAYLOAD"
        );
        let credential_scope = format!("{date}/{}/s3/aws4_request", self.region);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{}",
            hex_lower(&Sha256::digest(canonical_request.as_bytes()))
        );
        let signing_key = signing_key(&self.secret_key, &date, &self.region);
        let signature = hex_lower(&hmac_sha256(&signing_key, string_to_sign.as_bytes()));
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
            self.access_key
        );
        let headers = Headers::new();
        headers
            .set("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
            .map_err(|err| err.to_string())?;
        headers
            .set("x-amz-date", &amz_date)
            .map_err(|err| err.to_string())?;
        headers
            .set("authorization", &authorization)
            .map_err(|err| err.to_string())?;
        if let Some(range) = range {
            headers.set("range", range).map_err(|err| err.to_string())?;
        }
        Ok((url, headers))
    }
}

fn request_with_headers(url: &str, headers: Headers) -> Result<Request> {
    let mut init = RequestInit::new();
    init.with_method(Method::Get);
    init.with_headers(headers);
    Request::new_with_init(url, &init)
}

fn required_var(env: &worker::Env, name: &str) -> std::result::Result<String, String> {
    env.var(name)
        .map(|value| value.to_string())
        .map_err(|_| format!("missing required binding {name}"))
}

fn optional_var(env: &worker::Env, name: &str) -> Option<String> {
    env.var(name)
        .ok()
        .map(|value| value.to_string())
        .filter(|value| !value.is_empty())
}

fn r2_binding_name(env: &worker::Env) -> String {
    optional_var(env, "BZ_R2_BUCKET_BINDING").unwrap_or_else(|| "BZ_ARCHIVE_BUCKET".to_string())
}

fn s3_range_header(offset: u64, len: usize) -> std::result::Result<String, String> {
    let end = offset
        .checked_add(len as u64)
        .and_then(|value| value.checked_sub(1))
        .ok_or_else(|| "range end overflow".to_string())?;
    Ok(format!("bytes={offset}-{end}"))
}

fn validate_content_range(value: &str, offset: u64, len: usize) -> std::result::Result<(), String> {
    let expected_end = offset
        .checked_add(len as u64)
        .and_then(|end| end.checked_sub(1))
        .ok_or_else(|| "range end overflow".to_string())?;
    let (range, total) = value
        .strip_prefix("bytes ")
        .and_then(|value| value.split_once('/'))
        .ok_or_else(|| "invalid S3 Content-Range".to_string())?;
    let expected = format!("{offset}-{expected_end}");
    if range != expected
        || total
            .parse::<u64>()
            .ok()
            .is_none_or(|total| total <= expected_end)
    {
        return Err("S3 Content-Range differs from the requested range".into());
    }
    Ok(())
}

fn ensure_js_safe_range(offset: u64, len: usize) -> std::result::Result<(), String> {
    let len = len as u64;
    let end = offset
        .checked_add(len)
        .and_then(|value| value.checked_sub(1))
        .ok_or_else(|| "R2 range end overflow".to_string())?;
    let max = js_sys::Number::MAX_SAFE_INTEGER as u64;
    if offset > max || len > max || end > max {
        return Err(format!(
            "R2 range offset={offset} len={len} exceeds JavaScript safe integer limit {max}"
        ));
    }
    Ok(())
}

fn amz_dates() -> (String, String) {
    let now = js_sys::Date::new_0();
    let year = now.get_utc_full_year();
    let month = now.get_utc_month() + 1;
    let day = now.get_utc_date();
    let hour = now.get_utc_hours();
    let minute = now.get_utc_minutes();
    let second = now.get_utc_seconds();
    (
        format!("{year:04}{month:02}{day:02}"),
        format!("{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}Z"),
    )
}

fn signing_key(secret_key: &str, date: &str, region: &str) -> [u8; 32] {
    let k_date = hmac_sha256(format!("AWS4{secret_key}").as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, b"s3");
    hmac_sha256(&k_service, b"aws4_request")
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut key_block = [0u8; 64];
    if key.len() > 64 {
        key_block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36u8; 64];
    let mut outer_pad = [0x5cu8; 64];
    for i in 0..64 {
        inner_pad[i] ^= key_block[i];
        outer_pad[i] ^= key_block[i];
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner_hash = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_hash);
    let out = outer.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&out);
    bytes
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn uri_encode_path(path: &str) -> String {
    path.split('/')
        .map(uri_encode_path_segment)
        .collect::<Vec<_>>()
        .join("/")
}

fn uri_encode_path_segment(segment: &str) -> String {
    let mut out = String::new();
    for byte in segment.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn short_error_body(body: &str) -> String {
    let body = body.trim().replace(['\n', '\r', '\t'], " ");
    const MAX_LEN: usize = 300;
    if body.len() <= MAX_LEN {
        body
    } else {
        format!("{}...", &body[..MAX_LEN])
    }
}

fn range_fetch_profile_name(kind: StorageBackendKind, path: &str) -> &'static str {
    match kind {
        StorageBackendKind::R2 => {
            if path.ends_with(ARCHIVE_V2_GET_BLOCK_INDEX_FILE) {
                "r2_get_block_index"
            } else if path.ends_with(ARCHIVE_V2_BLOCKS_FILE) {
                "r2_blocks"
            } else if path.ends_with(ARCHIVE_V2_BLOCK_ACCESS_FILE) {
                "r2_meta_bin"
            } else {
                "r2_other"
            }
        }
        StorageBackendKind::S3 => {
            if path.ends_with(ARCHIVE_V2_GET_BLOCK_INDEX_FILE) {
                "s3_get_block_index"
            } else if path.ends_with(ARCHIVE_V2_BLOCKS_FILE) {
                "s3_blocks"
            } else if path.ends_with(ARCHIVE_V2_BLOCK_ACCESS_FILE) {
                "s3_meta_bin"
            } else {
                "s3_other"
            }
        }
    }
}

fn range_fetch_detail(path: &str, offset: u64, len: usize) -> String {
    let file = path.rsplit('/').next().unwrap_or(path);
    let end = offset.saturating_add(len as u64).saturating_sub(1);
    format!("{file} bytes={offset}-{end}")
}

fn cached_json_response<T: Serialize>(value: &T, cache_control: &str) -> Result<Response> {
    cached_json_response_profiled(value, cache_control, None)
}

fn cached_json_response_profiled<T: Serialize>(
    value: &T,
    cache_control: &str,
    profile: Option<&ProfileHandle>,
) -> Result<Response> {
    let headers = Headers::new();
    headers.set("Cache-Control", cache_control)?;
    headers.set("Content-Type", "application/json")?;
    add_profile_headers(&headers, profile)?;
    Ok(Response::from_json(value)?.with_headers(headers))
}

fn block_bundle_response_profiled(
    bytes: Vec<u8>,
    profile: Option<&ProfileHandle>,
) -> Result<Response> {
    let headers = Headers::new();
    let cache_control = if profile.is_some() {
        ERROR_CACHE_CONTROL
    } else {
        BLOCK_CACHE_CONTROL
    };
    headers.set("Cache-Control", cache_control)?;
    headers.set(
        "Content-Type",
        "application/vnd.blockzilla.get-block-bundle.wincode",
    )?;
    headers.set("Content-Length", &bytes.len().to_string())?;
    add_profile_headers(&headers, profile)?;
    Ok(Response::from_bytes(bytes)?.with_headers(headers))
}

fn json_error(status: u16, code: &str, message: &str) -> Result<Response> {
    json_error_profiled(status, code, message, None)
}

fn json_error_profiled(
    status: u16,
    code: &str,
    message: &str,
    profile: Option<&ProfileHandle>,
) -> Result<Response> {
    let headers = Headers::new();
    headers.set("Cache-Control", ERROR_CACHE_CONTROL)?;
    headers.set("Content-Type", "application/json")?;
    add_profile_headers(&headers, profile)?;
    Ok(Response::from_json(&json!({
        "ok": false,
        "error": {
            "code": code,
            "message": message,
        }
    }))?
    .with_status(status)
    .with_headers(headers))
}

fn add_profile_headers(headers: &Headers, profile: Option<&ProfileHandle>) -> Result<()> {
    let Some(profile) = profile else {
        return Ok(());
    };
    let server_timing = profile.server_timing();
    if !server_timing.is_empty() {
        headers.set("Server-Timing", &server_timing)?;
    }
    headers.set("X-BZ-Profile", &profile.profile_json().to_string())?;
    headers.set(
        "X-Blockzilla-Profile-Mode",
        if profile.source_ranges_only() {
            "source"
        } else {
            "full"
        },
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_exact_partial_response_bounds() {
        assert!(validate_content_range("bytes 10-19/20", 10, 10).is_ok());
        for value in [
            "bytes 0-19/20",
            "bytes 10-20/30",
            "bytes 10-19/19",
            "bytes 10-19/*",
            "10-19/20",
        ] {
            assert!(validate_content_range(value, 10, 10).is_err());
        }
        assert!(validate_content_range("bytes 0-0/1", u64::MAX, 2).is_err());
    }

    #[test]
    fn renders_optional_v1_transaction_config() {
        let value = transaction_config_value(&CompactTransactionConfig {
            priority_fee: Some(42),
            compute_unit_limit: None,
            loaded_accounts_data_size_limit: Some(65_536),
            heap_size: None,
        });
        assert_eq!(
            value,
            json!({"priorityFee":42, "computeUnitLimit":null,
            "loadedAccountsDataSizeLimit":65536, "heapSize":null})
        );
    }

    #[test]
    fn decodes_v1_account_message_after_transaction_config() {
        let message =
            ArchiveV2HotMessagePayload::V1(blockzilla_archive_v2::ArchiveV2HotV1Message {
                header: blockzilla_compact::CompactMessageHeader {
                    num_required_signatures: 1,
                    num_readonly_signed_accounts: 0,
                    num_readonly_unsigned_accounts: 0,
                },
                config: CompactTransactionConfig {
                    priority_fee: Some(42),
                    compute_unit_limit: Some(1_400_000),
                    loaded_accounts_data_size_limit: Some(65_536),
                    heap_size: Some(262_144),
                },
                account_keys: vec![CompactPubkey::Raw([7; 32])],
                recent_blockhash: OwnedCompactRecentBlockhash::Id(3),
                instructions: vec![blockzilla_archive_v2::ArchiveV2HotInstruction {
                    program_id_index: 1,
                    accounts: vec![0],
                    data: ArchiveV2HotInstructionData::Raw(vec![9]),
                }],
            });
        let bytes = wincode::config::serialize(&message, wincode_leb128_config())
            .expect("serialize v1 message");

        let decoded = decode_account_message_lite_bytes(&bytes, 9).expect("decode v1 accounts");

        assert!(matches!(decoded.version, AccountMessageVersion::V1));
        assert_eq!(decoded.header.num_required_signatures, 1);
        assert_eq!(decoded.account_keys, vec![CompactPubkey::Raw([7; 32])]);
        assert_eq!(decoded.program_id_indices, vec![1]);
    }

    #[test]
    fn renders_all_message_versions_for_buffered_and_streaming_paths() {
        let header = blockzilla_compact::CompactMessageHeader {
            num_required_signatures: 0,
            num_readonly_signed_accounts: 0,
            num_readonly_unsigned_accounts: 0,
        };
        let legacy =
            ArchiveV2HotMessagePayload::Legacy(blockzilla_archive_v2::ArchiveV2HotLegacyMessage {
                header,
                account_keys: Vec::new(),
                recent_blockhash: OwnedCompactRecentBlockhash::Id(0),
                instructions: Vec::new(),
            });
        let v0 = ArchiveV2HotMessagePayload::V0(blockzilla_archive_v2::ArchiveV2HotV0Message {
            header,
            account_keys: Vec::new(),
            recent_blockhash: OwnedCompactRecentBlockhash::Id(0),
            instructions: Vec::new(),
            address_table_lookups: Vec::new(),
        });
        let v1 = ArchiveV2HotMessagePayload::V1(blockzilla_archive_v2::ArchiveV2HotV1Message {
            header,
            config: CompactTransactionConfig {
                priority_fee: None,
                compute_unit_limit: None,
                loaded_accounts_data_size_limit: None,
                heap_size: None,
            },
            account_keys: Vec::new(),
            recent_blockhash: OwnedCompactRecentBlockhash::Id(0),
            instructions: Vec::new(),
        });

        for (message, expected_value, expected_json) in [
            (&legacy, Value::String("legacy".to_string()), "\"legacy\""),
            (&v0, Value::from(0), "0"),
            (&v1, Value::from(1), "1"),
        ] {
            assert_eq!(message_version_value(message), expected_value);
            let mut writer = JsonByteWriter::with_capacity(8);
            stream_message_version_value(&mut writer, message);
            assert_eq!(
                String::from_utf8(writer.into_inner()).unwrap(),
                expected_json
            );
        }

        for (version, expected_value, expected_json) in [
            (
                AccountMessageVersion::Legacy,
                Value::String("legacy".to_string()),
                "\"legacy\"",
            ),
            (AccountMessageVersion::V0, Value::from(0), "0"),
            (AccountMessageVersion::V1, Value::from(1), "1"),
        ] {
            assert_eq!(version.value(), expected_value);
            let mut writer = JsonByteWriter::with_capacity(8);
            stream_account_message_version_value(&mut writer, &version);
            assert_eq!(
                String::from_utf8(writer.into_inner()).unwrap(),
                expected_json
            );
        }
    }

    #[test]
    fn transaction_error_render_instruction_custom() {
        let decoded = StoredTransactionError::InstructionError(0, InstructionError::Custom(0));
        let mut err = JsonByteWriter::with_capacity(64);
        stream_optional_transaction_error(&mut err, Some(&decoded)).expect("write err");
        assert_eq!(
            String::from_utf8(err.into_inner()).expect("utf8 err"),
            r#"{"InstructionError":[0,{"Custom":0}]}"#
        );

        let mut status = JsonByteWriter::with_capacity(80);
        stream_transaction_status(&mut status, Some(&decoded)).expect("write status");
        assert_eq!(
            String::from_utf8(status.into_inner()).expect("utf8 status"),
            r#"{"Err":{"InstructionError":[0,{"Custom":0}]}}"#
        );
    }

    #[test]
    fn transaction_error_render_borsh_io_error_as_string() {
        let decoded = StoredTransactionError::InstructionError(
            238,
            InstructionError::BorshIoError("Unknown".to_string()),
        );
        let mut err = JsonByteWriter::with_capacity(64);
        stream_optional_transaction_error(&mut err, Some(&decoded)).expect("write err");
        assert_eq!(
            String::from_utf8(err.into_inner()).expect("utf8 err"),
            r#"{"InstructionError":[238,"BorshIoError"]}"#
        );
    }

    #[test]
    fn parses_all_direct_block_route_variants() {
        assert_eq!(
            direct_block_route("/block/123.bin").map(|(mode, slot)| (mode.metric_method(), slot)),
            Some(("getBlock", "123.bin"))
        );
        assert_eq!(
            direct_block_route("/block-lite/123.json")
                .map(|(mode, slot)| (mode.metric_method(), slot)),
            Some(("getBlockLite", "123.json"))
        );
        assert!(direct_block_route("/block/nested/123.bin").is_none());
    }

    #[test]
    fn renders_authoritative_cache_receipts() {
        assert_eq!(cache_receipt_value("hit"), "HIT");
        assert_eq!(cache_receipt_value("miss"), "MISS");
        assert_eq!(cache_receipt_value("uncached"), "UNCACHED");
        assert_eq!(cache_receipt_value("anything-else"), "BYPASS");
    }

    #[test]
    fn applies_rpc_log_messages_byte_limit() {
        let messages = (0..LOG_MESSAGES_BYTES_LIMIT + 1)
            .map(|_| "x".to_string())
            .collect();
        let limited = apply_log_messages_byte_limit(messages);
        assert_eq!(limited.len(), LOG_MESSAGES_BYTES_LIMIT);
        assert_eq!(limited.last().map(String::as_str), Some("Log truncated"));
    }
}
